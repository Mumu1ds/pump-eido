const path = require('path'), fs = require('fs');
const express = require('express'), mysql = require('mysql2/promise'),
  bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), crypto = require('crypto');

const app = express();
app.use(express.json());
const page = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
app.get('/', (req, res) => res.type('html').send(page));

const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', port: +process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root', password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'pump_eido', connectionLimit: 3,
  ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined
});
const SECRET = process.env.JWT_SECRET || 'troque-este-segredo';

const h = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Erro interno. Tente novamente.' }); });
const auth = (...roles) => (req, res, next) => {
  try {
    req.user = jwt.verify((req.headers.authorization || '').slice(7), SECRET);
    if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: 'Sem permissão.' });
    next();
  } catch { res.status(401).json({ error: 'Sessão expirada. Entre novamente.' }); }
};
const q = async (sql, p = []) => (await db.query(sql, p))[0];
const studentId = async uid => (await q('SELECT id FROM students WHERE user_id=?', [uid]))[0]?.id;
const token = u => jwt.sign({ id: u.id, role: u.role, name: u.name }, SECRET, { expiresIn: '7d' });

// ---------- Autenticação ----------
app.post('/api/auth/register', h(async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 6 || !['trainer', 'student'].includes(role))
    return res.status(400).json({ error: 'Preencha nome, e-mail válido e senha (mín. 6 caracteres).' });
  if ((await q('SELECT id FROM users WHERE email=?', [email])).length) return res.status(409).json({ error: 'E-mail já cadastrado.' });
  const r = await q('INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,?)', [name, email, await bcrypt.hash(password, 10), role]);
  if (role === 'student') await q('INSERT INTO students (user_id) VALUES (?)', [r.insertId]);
  const u = { id: r.insertId, role, name };
  res.json({ token: token(u), user: u });
}));

app.post('/api/auth/login', h(async (req, res) => {
  const [u] = await q('SELECT * FROM users WHERE email=?', [req.body.email || '']);
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password_hash)))
    return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  res.json({ token: token(u), user: { id: u.id, role: u.role, name: u.name } });
}));

// ---------- Profissional ----------
const T = auth('trainer');

app.get('/api/dashboard', T, h(async (req, res) => {
  const id = req.user.id;
  const [{ active }] = await q("SELECT COUNT(*) active FROM students WHERE trainer_id=? AND status='ativo'", [id]);
  const [{ week }] = await q(`SELECT COUNT(*) week FROM workout_sessions w JOIN students s ON s.id=w.student_id
    WHERE s.trainer_id=? AND w.finished_at > NOW() - INTERVAL 7 DAY`, [id]);
  const attention = await q(`SELECT u.name, DATEDIFF(NOW(), MAX(w.finished_at)) days FROM students s
    JOIN users u ON u.id=s.user_id LEFT JOIN workout_sessions w ON w.student_id=s.id
    WHERE s.trainer_id=? AND s.status='ativo' GROUP BY s.id, u.name
    HAVING days IS NULL OR days >= 7`, [id]);
  res.json({ active, week, attention });
}));

app.get('/api/students', T, h(async (req, res) => {
  res.json(await q(`SELECT s.id, u.name, u.email, s.goal, s.status,
    (SELECT MAX(finished_at) FROM workout_sessions w WHERE w.student_id=s.id) last_workout,
    (SELECT COUNT(*) FROM workout_sessions w WHERE w.student_id=s.id AND w.finished_at > NOW() - INTERVAL 30 DAY) sessions_30d
    FROM students s JOIN users u ON u.id=s.user_id WHERE s.trainer_id=? ORDER BY u.name`, [req.user.id]));
}));

app.post('/api/students', T, h(async (req, res) => {
  const { name, email, goal } = req.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Informe nome e e-mail válido.' });
  const [plan] = await q('SELECT p.max_students FROM users u JOIN plans p ON p.id=u.plan_id WHERE u.id=?', [req.user.id]);
  const [{ n }] = await q('SELECT COUNT(*) n FROM students WHERE trainer_id=?', [req.user.id]);
  if (plan.max_students !== null && n >= plan.max_students)
    return res.status(402).json({ error: 'Limite de alunos do seu plano atingido. Faça upgrade.' });
  if ((await q('SELECT id FROM users WHERE email=?', [email])).length) return res.status(409).json({ error: 'E-mail já cadastrado.' });
  const temp = crypto.randomBytes(4).toString('hex');
  const r = await q('INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,\'student\')', [name, email, await bcrypt.hash(temp, 10)]);
  await q('INSERT INTO students (user_id,trainer_id,goal) VALUES (?,?,?)', [r.insertId, req.user.id, goal || 'hipertrofia']);
  res.json({ ok: true, tempPassword: temp });
}));

app.get('/api/exercises', auth(), h(async (req, res) => res.json(await q('SELECT * FROM exercises ORDER BY muscle_group, name'))));

app.post('/api/workouts', T, h(async (req, res) => {
  const { student_id, name, exercises } = req.body;
  if (!name || !Array.isArray(exercises) || !exercises.length) return res.status(400).json({ error: 'Informe o nome e ao menos um exercício.' });
  // isolamento: só treina alunos da própria carteira
  if (!(await q('SELECT id FROM students WHERE id=? AND trainer_id=?', [student_id, req.user.id])).length)
    return res.status(403).json({ error: 'Aluno não pertence à sua carteira.' });
  const r = await q('INSERT INTO workouts (trainer_id,student_id,name) VALUES (?,?,?)', [req.user.id, student_id, name]);
  for (const [i, e] of exercises.entries())
    await q('INSERT INTO workout_exercises (workout_id,exercise_id,position,sets,reps,load_kg,rest_s) VALUES (?,?,?,?,?,?,?)',
      [r.insertId, e.exercise_id, i, +e.sets || 3, +e.reps || 10, +e.load_kg || 0, +e.rest_s || 60]);
  res.json({ ok: true });
}));

// ---------- Aluno ----------
const S = auth('student');

app.get('/api/me/workouts', S, h(async (req, res) => {
  const sid = await studentId(req.user.id);
  const ws = await q('SELECT id, name FROM workouts WHERE student_id=? AND archived=0 ORDER BY id DESC', [sid]);
  for (const w of ws) w.exercises = await q(`SELECT we.exercise_id, e.name, e.muscle_group, we.sets, we.reps, we.load_kg, we.rest_s
    FROM workout_exercises we JOIN exercises e ON e.id=we.exercise_id WHERE we.workout_id=? ORDER BY we.position`, [w.id]);
  res.json(ws);
}));

app.post('/api/me/sessions', S, h(async (req, res) => {
  const sid = await studentId(req.user.id), { workout_id, sets } = req.body;
  if (!(await q('SELECT id FROM workouts WHERE id=? AND student_id=?', [workout_id, sid])).length)
    return res.status(403).json({ error: 'Treino não encontrado.' });
  if (!Array.isArray(sets) || !sets.length) return res.status(400).json({ error: 'Conclua ao menos uma série.' });
  const volume = sets.reduce((a, s) => a + (+s.reps || 0) * (+s.load_kg || 0), 0);
  const r = await q('INSERT INTO workout_sessions (student_id,workout_id,volume) VALUES (?,?,?)', [sid, workout_id, volume]);
  for (const s of sets) await q('INSERT INTO workout_sets (session_id,exercise_id,set_no,reps,load_kg) VALUES (?,?,?,?,?)',
    [r.insertId, s.exercise_id, s.set_no, +s.reps, +s.load_kg]);
  const [prev] = await q('SELECT volume FROM workout_sessions WHERE student_id=? AND workout_id=? AND id<? ORDER BY id DESC LIMIT 1', [sid, workout_id, r.insertId]);
  res.json({ volume, previous: prev ? +prev.volume : null });
}));

app.get('/api/me/summary', S, h(async (req, res) => {
  const sid = await studentId(req.user.id);
  const [{ sessions }] = await q('SELECT COUNT(*) sessions FROM workout_sessions WHERE student_id=?', [sid]);
  const [{ ml }] = await q('SELECT COALESCE(SUM(ml),0) ml FROM water_logs WHERE student_id=? AND day=CURDATE()', [sid]);
  const weights = await q('SELECT weight, day FROM measurements WHERE student_id=? ORDER BY day, id', [sid]);
  res.json({ sessions, ml: +ml, weights });
}));

app.post('/api/me/water', S, h(async (req, res) => {
  const ml = +req.body.ml;
  if (![250, 500, 750, 1000].includes(ml)) return res.status(400).json({ error: 'Quantidade inválida.' });
  await q('INSERT INTO water_logs (student_id,ml,day) VALUES (?,?,CURDATE())', [await studentId(req.user.id), ml]);
  res.json({ ok: true });
}));

app.post('/api/me/measurements', S, h(async (req, res) => {
  const w = +req.body.weight;
  if (!(w > 20 && w < 400)) return res.status(400).json({ error: 'Informe um peso válido.' });
  await q('INSERT INTO measurements (student_id,weight,day) VALUES (?,?,CURDATE())', [await studentId(req.user.id), w]);
  res.json({ ok: true });
}));

// ---------- IA: treino e dieta automáticos ----------
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-haiku-4-5-20251001';
const SYS = 'Você organiza planos de treino e alimentação para adultos saudáveis, em português do Brasil. Não faz diagnóstico nem trata doenças. Havendo lesão, condição de saúde ou restrição, escolha opções conservadoras e recomende procurar um profissional. Responda SOMENTE com JSON válido, sem texto fora do JSON.';
async function askAI(user) {
  let t;
  if (process.env.GEMINI_API_KEY) { // IA gratuita (Google AI Studio)
    const m = process.env.GEMINI_MODEL || 'gemini-2.5-flash-lite';
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent`, {
      method: 'POST',
      headers: { 'x-goog-api-key': process.env.GEMINI_API_KEY, 'content-type': 'application/json' },
      body: JSON.stringify(/^gemma/.test(m) // Gemma não aceita instrução de sistema nem modo JSON
        ? { contents: [{ role: 'user', parts: [{ text: SYS + '\n\n' + user }] }], generationConfig: { maxOutputTokens: 8192 } }
        : { systemInstruction: { parts: [{ text: SYS }] }, contents: [{ role: 'user', parts: [{ text: user }] }],
            generationConfig: { responseMimeType: 'application/json', maxOutputTokens: 8192 } })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || 'falha na IA');
    t = (d.candidates?.[0]?.content?.parts || []).map(p => p.text || '').join('');
  } else { // Claude (pago)
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' },
      body: JSON.stringify({ model: MODEL, max_tokens: 3500, system: SYS, messages: [{ role: 'user', content: user }] })
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error?.message || 'falha na IA');
    t = d.content.map(c => c.text || '').join('');
  }
  return JSON.parse(t.slice(t.indexOf('{'), t.lastIndexOf('}') + 1));
}

async function genWorkout(sid, uid, p, fb) {
  const exs = await q('SELECT id,name,muscle_group,equipment FROM exercises');
  const out = await askAI(`Perfil: ${JSON.stringify(p)}
Exercícios disponíveis (use SOMENTE estes exercise_id): ${JSON.stringify(exs)}
Crie ${p.days} treinos (um por dia de treino), de 5 a 8 exercícios cada, adequados ao nível, objetivo e equipamento (${p.equipment}). Use load_kg 0 (o usuário ajusta a carga).
Pedido do usuário: ${fb || 'nenhum'}
Formato: {"workouts":[{"name":"Treino A — Peito e Tríceps","exercises":[{"exercise_id":1,"sets":4,"reps":10,"rest_s":90}]}]}`);
  const ids = new Set(exs.map(e => e.id));
  const ws = (out.workouts || []).slice(0, 6).map(w => ({ name: String(w.name || 'Treino').slice(0, 100),
    ex: (w.exercises || []).filter(e => ids.has(+e.exercise_id)).slice(0, 10) })).filter(w => w.ex.length);
  if (!ws.length) throw new Error('treino inválido');
  await q('UPDATE workouts SET archived=1 WHERE student_id=? AND trainer_id=?', [sid, uid]); // mantém o histórico
  for (const w of ws) {
    const r = await q('INSERT INTO workouts (trainer_id,student_id,name) VALUES (?,?,?)', [uid, sid, w.name]);
    for (const [i, e] of w.ex.entries())
      await q('INSERT INTO workout_exercises (workout_id,exercise_id,position,sets,reps,load_kg,rest_s) VALUES (?,?,?,?,?,0,?)',
        [r.insertId, e.exercise_id, i, Math.min(6, Math.max(1, +e.sets || 3)), Math.min(30, Math.max(1, +e.reps || 10)), Math.min(300, +e.rest_s || 60)]);
  }
  await q('INSERT INTO ai_plans (student_id,kind,feedback) VALUES (?,\'treino\',?)', [sid, fb || null]);
}

async function genDiet(sid, p, fb) {
  const age = new Date().getFullYear() - p.birth_year;
  const bmr = 10 * p.weight_kg + 6.25 * p.height_cm - 5 * age + (p.sex === 'M' ? 5 : -161); // Mifflin-St Jeor
  const adj = { emagrecimento: 0.85, hipertrofia: 1.1 }[p.goal] || 1;
  const kcal = Math.round(Math.max(p.sex === 'M' ? 1500 : 1200, bmr * (1.2 + 0.07 * p.days) * adj) / 10) * 10; // piso de segurança
  const protein = Math.round(p.weight_kg * (p.goal === 'hipertrofia' ? 2 : 1.8)), fat = Math.round(p.weight_kg * 0.9);
  const carbs = Math.max(50, Math.round((kcal - protein * 4 - fat * 9) / 4));
  const out = await askAI(`Perfil: ${JSON.stringify(p)}
Meta diária já calculada pelo sistema: ${kcal} kcal, ${protein}g proteína, ${carbs}g carboidratos, ${fat}g gorduras.
Monte um dia de alimentação com 5 refeições cuja soma fique próxima da meta, com alimentos comuns no Brasil. Respeite rigorosamente as restrições e preferências.
Pedido do usuário: ${fb || 'nenhum'}
Formato: {"meals":[{"name":"Café da manhã","foods":[{"food":"Ovos mexidos","qty":"3 unidades","kcal":210}]}],"notes":"observação curta"}`);
  const meals = (out.meals || []).slice(0, 8).map(m => ({ name: String(m.name || 'Refeição').slice(0, 40),
    foods: (m.foods || []).slice(0, 10).map(f => ({ food: String(f.food || '').slice(0, 60), qty: String(f.qty || '').slice(0, 30), kcal: Math.round(+f.kcal) || 0 })) })).filter(m => m.foods.length);
  if (!meals.length) throw new Error('dieta inválida');
  await q('INSERT INTO ai_plans (student_id,kind,feedback,content) VALUES (?,\'dieta\',?,?)',
    [sid, fb || null, JSON.stringify({ kcal, protein, carbs, fat, meals, notes: String(out.notes || '').slice(0, 300) })]);
}

app.get('/api/me/ai', S, h(async (req, res) => {
  const sid = await studentId(req.user.id);
  const [profile] = await q('SELECT * FROM ai_profiles WHERE student_id=?', [sid]);
  const [d] = await q('SELECT content FROM ai_plans WHERE student_id=? AND kind=\'dieta\' ORDER BY id DESC LIMIT 1', [sid]);
  const ws = await q('SELECT name FROM workouts WHERE student_id=? AND archived=0 ORDER BY id', [sid]);
  res.json({ profile: profile || null, diet: d ? JSON.parse(d.content) : null, workouts: ws.map(w => w.name) });
}));

app.post('/api/me/ai/plan', S, h(async (req, res) => {
  if (!process.env.GEMINI_API_KEY && !process.env.ANTHROPIC_API_KEY) return res.status(503).json({ error: 'A IA ainda não foi configurada no servidor.' });
  const b = req.body, sid = await studentId(req.user.id), uid = req.user.id;
  const p = { birth_year: +b.birth_year, sex: b.sex === 'F' ? 'F' : 'M', height_cm: +b.height_cm, weight_kg: +b.weight_kg,
    goal: String(b.goal || 'hipertrofia').slice(0, 30), level: String(b.level || 'iniciante').slice(0, 20),
    days: Math.min(6, Math.max(2, +b.days || 3)), equipment: String(b.equipment || 'academia').slice(0, 20),
    preferences: String(b.preferences || '').slice(0, 500), restrictions: String(b.restrictions || '').slice(0, 500) };
  const age = new Date().getFullYear() - p.birth_year;
  if (!b.ack) return res.status(400).json({ error: 'Aceite o termo para continuar.' });
  if (!(age >= 18 && age <= 90)) return res.status(400).json({ error: 'Os planos automáticos são só para maiores de 18 anos. Procure um profissional.' });
  if (!(p.height_cm > 120 && p.height_cm < 230 && p.weight_kg > 30 && p.weight_kg < 300)) return res.status(400).json({ error: 'Confira altura e peso.' });
  const [{ n }] = await q('SELECT COUNT(*) n FROM ai_plans WHERE student_id=? AND created_at > NOW() - INTERVAL 1 DAY', [sid]);
  if (n >= 6) return res.status(429).json({ error: 'Limite diário de gerações atingido. Tente amanhã.' });
  await q('REPLACE INTO ai_profiles (student_id,birth_year,sex,height_cm,weight_kg,goal,level,days,equipment,preferences,restrictions) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [sid, p.birth_year, p.sex, p.height_cm, p.weight_kg, p.goal, p.level, p.days, p.equipment, p.preferences, p.restrictions]);
  const fb = String(b.feedback || '').slice(0, 400), jobs = [];
  if (b.kind !== 'dieta') jobs.push(genWorkout(sid, uid, p, fb));
  if (b.kind !== 'treino') jobs.push(genDiet(sid, p, fb));
  try { await Promise.all(jobs); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(502).json({ error: 'A IA não conseguiu gerar agora (' + String(e.message).slice(0, 100) + '). Tente de novo.' }); }
}));

if (require.main === module) app.listen(process.env.PORT || 3000, () => console.log('Pump Eido em http://localhost:3000'));
module.exports = app; // a Vercel usa este export
