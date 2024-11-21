import express from 'express';
import mysql from 'mysql2';
import bcrypt from 'bcryptjs';
import bodyParser from 'body-parser';
import cors from 'cors';

const app = express();
const port = 5000;

// Настройка CORS для React
app.use(cors({
  origin: 'http://localhost:3000',
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type'],
}));

app.use(bodyParser.json());

// Подключение к базе данных
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '12345',
  database: 'socialnet',
});

db.connect((err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err);
    return;
  }
  console.log('Подключение к базе данных успешно!');
});

// Регистрация нового пользователя
app.post('/register', async (req, res) => {
  const { username, email, password, name } = req.body;

  if (!username || !email || !password || !name) {
    return res.status(400).json({ message: 'Все поля обязательны для заполнения!' });
  }

  try {
    // Хешируем пароль
    const hashedPassword = await bcrypt.hash(password, 10);

    // Запрос на вставку нового пользователя в базу данных
    const query = 'INSERT INTO users (username, email, password, name) VALUES (?, ?, ?, ?)';
    db.query(query, [username, email, hashedPassword, name], (err, result) => {
      if (err) {
        console.error('Ошибка при добавлении пользователя:', err);
        return res.status(500).json({ message: 'Ошибка сервера' });
      }

      console.log('Новый пользователь добавлен:', result);
      res.status(200).json({ message: 'Регистрация прошла успешно!' });
    });
  } catch (error) {
    console.error('Ошибка хеширования пароля:', error);
    res.status(500).json({ message: 'Ошибка хеширования пароля' });
  }
});

// Логин пользователя с использованием username
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Все поля обязательны для заполнения!' });
  }

  // Поиск пользователя по username
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], async (err, result) => {
    if (err) {
      console.error('Ошибка при поиске пользователя:', err);
      return res.status(500).json({ message: 'Ошибка сервера' });
    }

    if (result.length === 0) {
      // Пользователь не найден
      return res.status(400).json({ message: 'Неверный username или пароль' });
    }

    const user = result[0];

    try {
      // Сравнение пароля
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (isPasswordValid) {
        // Успешная авторизация
        console.log('Пользователь авторизован:', user);
        res.status(200).json({ message: 'Успешный вход', user });
      } else {
        // Неверный пароль
        res.status(400).json({ message: 'Неверный username или пароль' });
      }
    } catch (error) {
      console.error('Ошибка при проверке пароля:', error);
      res.status(500).json({ message: 'Ошибка при проверке пароля' });
    }
  });
});

// Запуск сервера
app.listen(port, () => {
  console.log(`Сервер работает на http://localhost:${port}`);
});
