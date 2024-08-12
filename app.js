const db = require('./db/database');
const express = require('express')
const app = express()
const cors = require('cors');
const port = 4000
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken")
const cookieParser = require('cookie-parser');
const { key, secretKey } = require('./key');

app.use(express.json());
app.use(cors({
    origin: '*',
    credentials: true
  }));
  
  app.use(cookieParser());



  app.post('/register', async (req, res) => {
    const { name, password, apellidos, email } = req.body;

    try {

        const existingUserQuery = `SELECT * FROM usuarios WHERE nombre_usuario = ? OR email = ?`;
        const existingUsers = await db.query(existingUserQuery, [name, email]);

        if (existingUsers.length > 0) {
            return res.status(400).json({ message: 'El nombre de usuario o el correo electrónico ya están en uso.' });
        }

  
        const hashedPassword = await bcrypt.hash(password, 10);


        const insertUserQuery = `INSERT INTO usuarios (nombre_usuario, contraseña, apellidos, email) VALUES (?, ?, ?, ?)`;
        await db.query(insertUserQuery, [name, hashedPassword, apellidos, email]);


        const newUserQuery = `SELECT * FROM usuarios WHERE nombre_usuario = ?`;
        const newUser = await db.query(newUserQuery, [name]);

        if (newUser.length === 1) {
            const user = newUser[0];
            const userData = {
                idUsuario: user.id,
                usuario: user.nombre_usuario,
                apellidos: user.apellidos,
                correo: user.email,
            };

           
            const token = jwt.sign({ secretKey }, key, { expiresIn: "1h" });

            res.json({
                message: 'Registro exitoso',
                usuario: userData,
                token 
            });
        } else {
            res.status(500).json({ message: 'Error al registrar el usuario' });
        }
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

app.post('/login', async (req, res) => {
    const { name, password } = req.body;

    try {
        const query = `SELECT * FROM usuarios WHERE nombre_usuario = ? AND contraseña = ?`;
        const users = await db.query(query, [name, password]);

        if (users.length === 1) {
            const user = users[0];
            const userData = {
                idUsuario: user.id,
                usuario: user.nombre_usuario,
                apellidos: user.apellidos,
                correo: user.email,
                contraseña: user.contraseña
            };

            const token = jwt.sign({ secretKey }, key, { expiresIn: "1h" });

            res.json({
                message: 'Inicio de sesión exitoso',
                usuario: userData,
                token 
            });
        } else {
            res.status(404).json({ message: 'Correo o contraseña incorrectos.' });
        }
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});


app.get('/usuario/:email', async (req, res) => {
  const email = req.params.email;
  let rolData ={}
  try{

    const query = `SELECT * FROM vista_usuarios_roles WHERE email = ?;`;
    const rolResponse = await db.query(query, [email]);

    if (rolResponse.length > 0) {
      const rol_usuario = rolResponse[0];

       rolData = {
        emailUser: rol_usuario.email,
        nombre_Usuario: rol_usuario.nombre_usuario,
        tipoRol_Usuario: rol_usuario.nombre_rol

      }
    }else{
      return res.status(404).send('Usuario no encontrado');
    }

    res.json({
      message: 'Los datos del usuario encontrado son:',
      usuario: rolData
  });

  }catch(error){

    res.status(404).send('Usuario no encontrado');

  }

});



app.get("/obtenerProductos", verifyToken, (req, res) => {
    const productos = {
        "productos": [
            {
                "id": 1,
                "nombre": "Coca Cola",
                "precio": 2100,
                "descripcion": "3 Litros"
            },
            {
                "id": 2,
                "nombre": "Pepsi",
                "precio": 1800,
                "descripcion": "3 Litros"
            },
            {
                "id": 3,
                "nombre": "Big Cola",
                "precio": 1200,
                "descripcion": "3 Litros"
            }
        ]
    };

    res.send(productos);
});

app.get('/perfil', async (req, res) => {
    const userEmail = req.user.email;
    
  
    try {
      const query = `SELECT * FROM usuarios WHERE email = ? `;
      const [rows] = await db.query(query, [userEmail]);
      console.log('Resultados del token:', userEmail);
      console.log('Resultados de la consulta:', rows.id);
  
      if (rows) {
        const data = rows;
        const dataPerfil = {
          idUsuario: data.id,
          usuario: data.nombre_usuario,
          apellidos: data.apellidos,
          correo: data.email
        };
        res.json({ message: 'Usuario autenticado', dataPerfil });
      } else {
        res.status(404).json({ error: 'Usuario no encontrado en la base de datos' });
      }
    } catch (error) {
      console.error('Error al obtener datos del usuario:', error);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
  });

function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(403).json({ error: 'Token de autenticación no proporcionado' });
    }

    const token = authHeader.split(' ')[1]; // Extraer solo el token

    jwt.verify(token, key, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Token de autenticación inválido' });
        }
        req.user = decoded;
        next();
    });
}



app.listen(port, () => {
    console.log(`Aplicacion corriendo en el puerto: ${port}`);
})
