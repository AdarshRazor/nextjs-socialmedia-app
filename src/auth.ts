import {PrismaAdapter} from '@lucia-auth/adapter-prisma';
import prisma from './lib/prisma';
import { Lucia, Session, User} from 'lucia';
import {cache} from 'react';
import { cookies } from 'next/headers';

const adapter = new PrismaAdapter(prisma.session, prisma.user);

export const lucia = new Lucia(adapter, {
    sessionCookie: {
        expires: false,
        attributes: {
            secure: process.env.NODE_ENV === 'production'
        }
    },
    getUserAttributes(databaseUserAttributes:any): databaseUserAttributes{
        // when wew fetch the data on frontend we automatically get the below data
        return {
            id: databaseUserAttributes.id,
            username: databaseUserAttributes.username,
            displayName: databaseUserAttributes.displayName,
            avatarUrl: databaseUserAttributes.avatarUrl,
            googleId: databaseUserAttributes.googleId,
        }
    },
})

declare module "lucia" {
    interface Register {
        lucia: typeof lucia;
        DatabaseAttributes: databaseUserAttributes;
    }
}

interface databaseUserAttributes{
    id: string,
    username: string,
    displayName: string,
    avatarUrl: string|null,
    googleId: string|null,
}

export const validateRequest = cache(
    async(): Promise<
        {user: User ; session: Session} | {user: null; session: null}
    > => {
        const cookieStore = cookies();
        const sessionId = cookieStore.get(lucia.sessionCookieName)?.value ?? null; // Access the value of the cookie

        if (!sessionId) {
            return {
                user:null,
                session: null
            }
        }

        const result = await lucia.validateSession(sessionId);

        if (result.valid) {
            return {
                user: result.user,
                session: result.session,
            }
        } else {
            return {
                user: null,
                session: null,
            }
        }

    }
)