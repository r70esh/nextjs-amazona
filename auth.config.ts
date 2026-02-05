import type { NextAuthConfig } from 'next-auth'
import type { NextRequest } from 'next/server'
import type { Session } from 'next-auth'

export default {
  providers: [], // leave empty, defined in NextAuth()
  callbacks: {
    authorized({ request, auth }: { request: NextRequest; auth: Session | null }) {
      const protectedPaths = [
        /\/checkout(\/.*)?/,
        /\/account(\/.*)?/,
        /\/admin(\/.*)?/,
      ]

      const pathname = request.nextUrl.pathname

      // If the path is protected, only allow if auth exists
      if (protectedPaths.some((p) => p.test(pathname))) {
        return !!auth
      }

      // Otherwise allow
      return true
    },
  },
} satisfies NextAuthConfig
