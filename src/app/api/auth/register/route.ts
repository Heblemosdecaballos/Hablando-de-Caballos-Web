import { NextRequest, NextResponse } from 'next/server'
import { supabase } from '@/lib/supabase'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'

export async function POST(request: NextRequest) {
  try {
    const { username, email, password, fullName, userType, phone, location } = await request.json()

    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .or(`email.eq.${email},username.eq.${username}`)
      .single()

    if (existingUser) {
      return NextResponse.json({ error: 'El usuario o email ya existe' }, { status: 400 })
    }

    const passwordHash = await bcrypt.hash(password, 12)

    const { data: newUser, error } = await supabase
      .from('users')
      .insert({
        username,
        email,
        password_hash: passwordHash,
        full_name: fullName,
        user_type: userType,
        phone,
        location,
        is_admin: false,
        is_active: true
      })
      .select()
      .single()

    if (error) {
      return NextResponse.json({ error: 'Error al crear el usuario' }, { status: 500 })
    }

    const token = jwt.sign(
      { userId: newUser.id, email: newUser.email, isAdmin: newUser.is_admin },
      process.env.JWT_SECRET!,
      { expiresIn: '7d' }
    )

    return NextResponse.json({
      success: true,
      message: 'Usuario creado exitosamente',
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        fullName: newUser.full_name,
        isAdmin: newUser.is_admin
      },
      token
    })

  } catch (error) {
    return NextResponse.json({ error: 'Error interno del servidor' }, { status: 500 })
  }
}
