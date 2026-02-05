import { MongoDBAdapter } from '@auth/mongodb-adapter'
import Google from 'next-auth/providers/google'
import CredentialsProvider from 'next-auth/providers/credentials'
import bcrypt from 'bcryptjs'
import { connectToDatabase } from './lib/db'
import client from './lib/db/client'
import User from './lib/db/models/user.model'

import NextAuth, { type DefaultSession } from 'next-auth'
import authConfig from './auth.config'

// Extend the NextAuth session type
declare module 'next-auth' {
  interface Session {
    user: {
      id: string
      role: string
    } & DefaultSession['user']
  }
}

export const { handlers, auth, signIn, signOut } = NextAuth({
  ...authConfig,
  pages: {
    signIn: '/sign-in',
    newUser: '/sign-up',
    error: '/sign-in',
  },
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  adapter: MongoDBAdapter(client),
  providers: [
    Google({
      allowDangerousEmailAccountLinking: true,
    }),
    CredentialsProvider({
      credentials: {
        email: { type: 'email' },
        password: { type: 'password' },
      },
      async authorize(credentials: Record<string, any> | undefined) {
        await connectToDatabase()

        if (!credentials?.email || !credentials?.password) return null

        const user = await User.findOne({ email: credentials.email })
        if (!user || !user.password) return null

        const isMatch = await bcrypt.compare(
          credentials.password as string,
          user.password as string
        )
        if (!isMatch) return null

        const userName = user.name || (user.email ? user.email.split('@')[0] : 'User')

        return {
          id: user._id.toString(),
          name: userName,
          email: user.email,
          role: user.role || 'user',
        }
      },
    }),
  ],
  callbacks: {
    jwt: async ({ token, user, trigger, session }) => {
      if (user) {
        const userName = user.name || (user.email ? user.email.split('@')[0] : 'User')
        token.name = userName
        token.role = (user as { role: string })?.role || 'user'

        // Update DB if name is missing
        if (!user.name) {
          await connectToDatabase()
          await User.findByIdAndUpdate(user.id, {
            name: userName,
            role: token.role,
          })
        }
      }

      if (session?.user?.name && trigger === 'update') {
        token.name = session.user.name
      }

      return token
    },
    session: async ({ session, user, trigger, token }) => {
      session.user.id = token.sub as string
      session.user.role = token.role as string
      session.user.name = token.name || 'User'

      if (trigger === 'update' && user?.name) {
        session.user.name = user.name
      }

      return session
    },
  },
})
