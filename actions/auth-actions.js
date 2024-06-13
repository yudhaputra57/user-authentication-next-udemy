'use server';

import { createAuthSession, DestroySession } from "@/lib/auth";
import { hashUserPassword, verifyPassword } from "@/lib/hash";
import { CreateUser, getUserByEmail } from "@/lib/user";
import { redirect } from "next/navigation";

export async function SignUp(prevState, formData){
    const email = formData.get('email');
    const password = formData.get('password');

    let errors = {};

    if(!email.includes('@')){
        errors.email = 'Please enter a valid email address.';
    }

    if(password.trim().length < 8){
        errors.password = 'Password must be at least 8 characters long.';
    }

    if(Object.keys(errors).length > 0)
    {
        return {
            errors,
        }
    }

    const hashedPassword = hashUserPassword(password);
    try {
        const userId = CreateUser(email, hashedPassword);
        await createAuthSession(userId);
        redirect('/training');
    } catch(error){
        if(error.code == 'SQLITE_CONSTRAINT_UNIQUE'){
            return {
                errors: {
                    email: 'It seems like an account for the chosen email already exists.'
                }
            }
        }
        throw error;
    }
}

export async function login(prevState, formData){
    const email = formData.get('email')
    const password = formData.get('password')

    const existingUser = getUserByEmail(email)

    if(!existingUser){
        return {
            errors: {
                email: 'Could not authenticate user, please check your credentials'
            }
        }
    }

    const isValidPassword = verifyPassword(existingUser.password, password);

    if(!isValidPassword){
        return {
            errors: {
                password: 'Could not authenticate user, please check your credentials'
            }
        }
    }

    await createAuthSession(existingUser.id);
    redirect('/training');
}

export async function auth(mode, prevState, formData){
    if(mode === 'login'){
        return login(prevState, formData)
    }
    return SignUp(prevState, formData)
}

export async function logout(){
    const result = await DestroySession();
    redirect('/');
}