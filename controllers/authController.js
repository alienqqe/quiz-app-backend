const bcrypt = require('bcrypt')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const supabase = require('../supabaseClient')
const dotenv = require('dotenv')

dotenv.config()

const REFRESH_SECRET = process.env.REFRESH_SECRET
const JWT_SECRET = process.env.JWT_SECRET

exports.register = async (req, res) => {
  const token = req.cookies.refreshToken
  if (token) {
    await fetch(`${process.env.BACKEND_URL}/api/auth/logout`)
  }
  const { username, password } = req.body

  try {
    const hashed = await bcrypt.hash(password, 10)

    const { data: existingUser, error: fetchError } = await supabase
      .from('users')
      .select('username')
      .eq('username', username)
      .limit(1)

    if (fetchError) {
      return res.status(400).json({ error: fetchError.message })
    }

    if (existingUser.length > 0) {
      return res.status(400).json({
        error: 'User with this username already exists',
      })
    }
    const { data, error } = await supabase
      .from('users')
      .insert([
        {
          username,
          password: hashed,
          quizes: [],
        },
      ])
      .select()

    if (error) {
      return res.status(400).json({ error: error.message })
    }

    res.status(201).json({
      message: 'User registered',
      user: data[0],
    })
  } catch (err) {
    console.error('Register error', err)
    res.status(500).json({ error: 'Server error', message: err.message })
  }
}

exports.login = async (req, res) => {
  const existingToken = req.cookies.refreshToken

  if (existingToken) {
    try {
      const payload = jwt.verify(existingToken, REFRESH_SECRET)

      const { error: updateError } = await supabase
        .from('users')
        .update({ refresh_token: null })
        .eq('id', payload.id)

      if (updateError) {
        return res.status(400).json({ error: updateError.message })
      }

      res.clearCookie('refreshToken')
      res.clearCookie('accessToken')
    } catch (err) {
      res.clearCookie('refreshToken')
      res.clearCookie('accessToken')

      res.json({ err })
    }
  }

  const { username, password } = req.body

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('username', username)
    .single()

  if (error || !user) return res.status(401).json({ message: 'Invalid creds' })

  const valid = await bcrypt.compare(password, user.password)
  if (!valid) return res.status(401).json({ message: 'Invalid creds' })

  // issue tokens
  const accessToken = jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    {
      expiresIn: '15m',
    }
  )
  const refreshToken = jwt.sign(
    { id: user.id, username: user.username },
    REFRESH_SECRET,
    {
      expiresIn: '7d',
    }
  )

  const { error: updateErr } = await supabase
    .from('users')
    .update({
      refresh_token: refreshToken,
      updated_at: new Date().toISOString(),
    })
    .eq('id', user.id)

  if (updateErr) {
    return res.status(400).json({ error: updateErr.message })
  }

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000,
  })

  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: false,
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  })

  res.json({ accessToken })
}

exports.refresh = async (req, res) => {
  const token = req.cookies.refreshToken
  if (!token) return res.sendStatus(401)

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('refresh_token', token)
    .single()

  if (error || !user) return res.sendStatus(403).json(error)

  jwt.verify(token, REFRESH_SECRET, (err) => {
    if (err) return res.json({ error: { message: err.message } })

    const newAccessToken = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      {
        expiresIn: '15m',
      }
    )
    res.json({ accessToken: newAccessToken })
  })
}

exports.logout = async (req, res) => {
  const token = req.cookies.refreshToken

  if (token) {
    const { error: updateError } = await supabase
      .from('users')
      .update({ refresh_token: null })
      .eq('refresh_token', token)

    if (updateError) {
      return res.status(400).json({ error: updateError.message })
    }
  }

  res.clearCookie('refreshToken')
  res.json({ message: 'Logged out' })
}

exports.me = async (req, res) => {
  const { data, error } = await supabase
    .from('users')
    .select('id, username')
    .eq('id', req.user.id)
    .single()

  if (error) return res.status(400).json(error)
  res.json(data)
}
