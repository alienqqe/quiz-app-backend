const express = require('express')
const cors = require('cors')
const crypto = require('crypto')
const cookieParser = require('cookie-parser')
const bcrypt = require('bcrypt')

require('dotenv').config()

const authRoutes = require('./routes/authRoutes')
const historyRoutes = require('./routes/historyRoutes')

const app = express()

const corsOptions = {
  origin: [
    'http://localhost:3000',
    'https://euphonious-cocada-ac9319.netlify.app/',
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}

app.use(cors(corsOptions))

app.use(express.json())
app.use(cookieParser())

app.use('/api/auth', authRoutes)
app.use('/api/history', historyRoutes)

const PORT = process.env.PORT || 4000
app.listen(PORT, () => console.log(`Server is listening on port ${PORT}`))
