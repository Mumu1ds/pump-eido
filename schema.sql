
CREATE TABLE plans (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(20) NOT NULL,
  price DECIMAL(8,2) NOT NULL,
  max_students INT NULL -- NULL = ilimitado
);

CREATE TABLE users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(120) NOT NULL,
  email VARCHAR(160) NOT NULL UNIQUE,
  password_hash VARCHAR(100) NOT NULL,
  role ENUM('trainer','student','admin') NOT NULL,
  plan_id INT NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (plan_id) REFERENCES plans(id)
);

CREATE TABLE students (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL UNIQUE,
  trainer_id INT NULL,
  goal VARCHAR(40) DEFAULT 'hipertrofia',
  height_cm INT NULL,
  status ENUM('ativo','inativo') DEFAULT 'ativo',
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (trainer_id) REFERENCES users(id),
  INDEX (trainer_id)
);

CREATE TABLE exercises (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(100) NOT NULL,
  muscle_group VARCHAR(30) NOT NULL,
  equipment VARCHAR(40)
);

CREATE TABLE workouts (
  id INT PRIMARY KEY AUTO_INCREMENT,
  trainer_id INT NOT NULL,
  student_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (trainer_id) REFERENCES users(id),
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  INDEX (student_id)
);

CREATE TABLE workout_exercises (
  id INT PRIMARY KEY AUTO_INCREMENT,
  workout_id INT NOT NULL,
  exercise_id INT NOT NULL,
  position INT NOT NULL,
  sets INT NOT NULL DEFAULT 3,
  reps INT NOT NULL DEFAULT 10,
  load_kg DECIMAL(6,2) DEFAULT 0,
  rest_s INT DEFAULT 60,
  FOREIGN KEY (workout_id) REFERENCES workouts(id) ON DELETE CASCADE,
  FOREIGN KEY (exercise_id) REFERENCES exercises(id)
);

CREATE TABLE workout_sessions (
  id INT PRIMARY KEY AUTO_INCREMENT,
  student_id INT NOT NULL,
  workout_id INT NOT NULL,
  finished_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  volume DECIMAL(10,2) DEFAULT 0,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  FOREIGN KEY (workout_id) REFERENCES workouts(id) ON DELETE CASCADE,
  INDEX (student_id, finished_at)
);

CREATE TABLE workout_sets (
  id INT PRIMARY KEY AUTO_INCREMENT,
  session_id INT NOT NULL,
  exercise_id INT NOT NULL,
  set_no INT NOT NULL,
  reps INT NOT NULL,
  load_kg DECIMAL(6,2) NOT NULL,
  FOREIGN KEY (session_id) REFERENCES workout_sessions(id) ON DELETE CASCADE,
  FOREIGN KEY (exercise_id) REFERENCES exercises(id)
);

CREATE TABLE water_logs (
  id INT PRIMARY KEY AUTO_INCREMENT,
  student_id INT NOT NULL,
  ml INT NOT NULL,
  day DATE NOT NULL,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  INDEX (student_id, day)
);

CREATE TABLE measurements (
  id INT PRIMARY KEY AUTO_INCREMENT,
  student_id INT NOT NULL,
  weight DECIMAL(5,2) NOT NULL,
  day DATE NOT NULL,
  FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
  INDEX (student_id, day)
);

CREATE TABLE messages (
  id INT PRIMARY KEY AUTO_INCREMENT,
  from_user INT NOT NULL,
  to_user INT NOT NULL,
  body TEXT NOT NULL,
  read_at DATETIME NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (from_user) REFERENCES users(id),
  FOREIGN KEY (to_user) REFERENCES users(id),
  INDEX (to_user, read_at)
);

INSERT INTO plans (name, price, max_students) VALUES ('FREE',0,3),('PRO',49,30),('PREMIUM',99,NULL);

INSERT INTO exercises (name, muscle_group, equipment) VALUES
('Supino reto','peito','barra'),('Crucifixo','peito','halteres'),
('Puxada frontal','costas','polia'),('Remada curvada','costas','barra'),
('Desenvolvimento','ombros','halteres'),('Elevação lateral','ombros','halteres'),
('Rosca direta','bíceps','barra'),('Tríceps corda','tríceps','polia'),
('Agachamento','quadríceps','barra'),('Stiff','posterior','barra'),
('Elevação pélvica','glúteos','barra'),('Panturrilha em pé','panturrilha','máquina'),
('Abdominal','abdômen','peso corporal'),('Esteira','cardio','esteira');
