const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

// Conectar a MongoDB
mongoose.connect('mongodb://localhost:27017/tuBaseDeDatos', {});

// Middleware para parsear JSON
app.use(express.json());

// Modelo de Usuario
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}));

// Ruta para el registro de usuario
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Faltan datos');

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword });

  try {
    await user.save();
    res.status(201).send('Usuario registrado con éxito');
  } catch (error) {
    res.status(400).send('Error al registrar el usuario');
  }
});

// Ruta para el inicio de sesión
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('Faltan datos');

  const user = await User.findOne({ username });
  if (!user) return res.status(400).send('Usuario no encontrado');

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).send('Contraseña incorrecta');

  const token = jwt.sign({ id: user._id }, 'secreto', { expiresIn: '1h' });
  res.status(200).send({ message: 'Autenticación satisfactoria', token });
});

// Ruta para actualizar un usuario
app.put('/update', async (req, res) => {
  const { username, newUsername, newPassword } = req.body;
  if (!username || (!newUsername && !newPassword)) return res.status(400).send('Faltan datos');

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).send('Usuario no encontrado');

    if (newUsername) user.username = newUsername;
    if (newPassword) user.password = await bcrypt.hash(newPassword, 10);

    await user.save();
    res.status(200).send('Usuario actualizado con éxito');
  } catch (error) {
    res.status(400).send('Error al actualizar el usuario');
  }
});

// Ruta para eliminar un usuario
app.delete('/delete', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).send('Faltan datos');

  try {
    const user = await User.findOneAndDelete({ username });
    if (!user) return res.status(404).send('Usuario no encontrado');

    res.status(200).send('Usuario eliminado con éxito');
  } catch (error) {
    res.status(400).send('Error al eliminar el usuario');
  }
});

// Ruta para listar todos los usuarios sin las contraseñas
app.get('/users', async (req, res) => {
  try {
    const users = await User.find({}).select('-password');
    res.status(200).json(users);
  } catch (error) {
    res.status(400).send('Error al obtener los usuarios');
  }
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
