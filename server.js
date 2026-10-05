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
  const r = await q('INSERT INTO users (name,email,password_hash,role) VALUES (?,?,?,"student")', [name, email, await bcrypt.hash(temp, 10)]);
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
  const ws = await q('SELECT id, name FROM workouts WHERE student_id=? ORDER BY id DESC', [sid]);
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

if (require.main === module) app.listen(process.env.PORT || 3000, () => console.log('Pump Eido em http://localhost:3000'));
module.exports = app; // a Vercel usa este export
