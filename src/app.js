import express from "express"
import users from "./database"
import { v4 as uuidv4 } from "uuid"
import * as bcrypt from "bcryptjs"
import jwt from "jsonwebtoken";

const app = express()
app.use(express.json())

// 1. MIDDLEWARES 

const verifyEmailAvailabilityMiddleware = (request, response, next) => {
    
    const { email } = request.body
    const userAlreadyExists = users.find((user) => user.email === email)

    if(userAlreadyExists){
        return response
        .status(409)
        .json({ 
            message: 'E-mail already registered'
        })
    }

    return next()
}

const verifyAuthTokenMiddleware = (request, response, next) => {

    let token = request.headers.authorization
    
    if(!token){
        return response
        .status(401)
        .json({ message: 'Missing authorization headers'})
    }

    token = token.split(" ")[1]

    jwt.verify(token, "SECRET_KEY", (error, decoded) => {

        if(error){
            return response
            .status(401)
            .json({ message: 'Invalid token'})
        }

        request.user = {
            email: decoded.email,
            uuid: decoded.sub,
        }
        
        return next();
    })
}

const verifyUserId = (request, response, next) => {

    const { id } = request.params
    const { uuid } = request.user
    const user = users.find((element) => element.uuid === uuid)

    if(!id === uuid){
        return response
        .status(403)
        .json({ 
            message: 'User is not the owner'
        })
    }
    
    return next()
}

const verifyUserIsAdmin = (request, response, next) => {

    const { uuid } = request.user
    const { id } = request.params
    const user = users.find((element) => element.uuid === uuid)

    if(!user.isAdm && id !== uuid ){
        return response
        .status(403)
        .json({ 
            message: 'Missing admin permissions'
        })
    }
    
    return next()
}

// 2. SERVICES 

const createUserService = async (name, email, password, isAdm) => {

    const hashedPassword = await bcrypt.hash(password, 10)
    const createdOn = new Date()
    const uuid = uuidv4()

    const newUser = {
        name,
        email,
        password: hashedPassword,
        isAdm,
        createdOn,
        updatedOn: createdOn, 
        uuid,
    }
    
    users.push(newUser)

    const user = {
        name,
        email,
        isAdm,
        createdOn,
        updatedOn: createdOn, 
        uuid,
    }

    return user
}

const userLoginService = (email, password) => {

    const user = users.find((element) => element.email === email)

    if (!user){
        throw new Error('Invalid e-mail or password!')
    }

    const passwordMatch = bcrypt.compareSync(password, user.password)

    if (!passwordMatch){
        throw new Error('Invalid e-mail or password!')
    }

    const token = jwt.sign({email: email}, "SECRET_KEY", {expiresIn: "24h", subject: user.uuid})

    return token

}

const listUserService = () => {
    
    return users
}

const userProfileService = (uuid) => {

    const user = users.find((element) => element.uuid === uuid)

    const profile = {
        uuid: user.uuid,
        name: user.name,
        email: user.email,
        isAdm: user.isAdm,
        createdOn: user.createdOn,
        updatedOn: user.updatedOn,
    }

    return profile

}

const updateUserService = async ({id, name, email, password}) => {
        
    const user = users.find((element) => element.uuid === id)
    
    if(!user){
        throw new Error('User not found')        
    }

    let newHashPassword = ''
    if(password){
        newHashPassword = await bcrypt.hash(password, 10)
    }

    const updatedUser = {
        name: name || user.name, 
        email: email || user.email,
        password: newHashPassword || user.password,
        updatedOn: new Date()
    }
    
    users[user] = {...users[user], ...updatedUser}

    const update = {
        uuid: id,
        name: updatedUser.name,
        email: updatedUser.email,
        updatedOn: updatedUser.updatedOn,
        createdOn: user.createdOn,
        isAdm: user.isAdm,
    }

    return update
}

const deleteUserService = (id) => {
    
    const userIndex = users.findIndex(element => element.uuid === id)

    if(userIndex === -1){
        throw new Error('User not found!')
    }

    users.splice(userIndex, 1)

    return {message: 'User deleted!'}
}

// 3. CONTROLLERS

const createUserController = async (request, response) => {
    const { name, email, password, isAdm } = request.body    
    const newUser = await createUserService(name, email, password, isAdm)
    return response.status(201).json(newUser)
}

const userLoginController = (request, response) => {
    try {
        const { email, password } = request.body    
        const userLogin = userLoginService(email, password)
        return response.json({
            token: userLogin
        })
    } catch (error) {
        return response.status(401).json({
            message: error.message
        })
    }
}

const listUserController = (request, response) => {
    const users = listUserService()
    return response.json(users)
}

const userProfileController = (request, response) => {
    const { uuid } = request.user
    const profile = userProfileService(uuid)
    return response.json(profile)
}

const updateUserController = async (request, response) => {
    
    try {
        const { id } = request.params
        const { name, email, password } = request.body
        const updatedUser = await updateUserService({id, name, email, password})
        return response.json(updatedUser)
    } catch (error) {
        return response.status(401).json({
            message: error.message
        })
    }
}

const deleteUserController = (request, response) => {
    const { id } = request.params
    const deletedUser = deleteUserService(id)
    return response.status(204).json(deletedUser)
}

// 4. ROTAS

app.post('/login', userLoginController);

app.post('/users', verifyEmailAvailabilityMiddleware, createUserController);
app.get('/users', verifyAuthTokenMiddleware, verifyUserIsAdmin, listUserController);
app.get('/users/profile', verifyAuthTokenMiddleware, userProfileController);
app.patch('/users/:id', verifyAuthTokenMiddleware, verifyUserId, verifyUserIsAdmin, updateUserController);
app.delete('/users/:id', verifyAuthTokenMiddleware, verifyUserIsAdmin, verifyUserId, deleteUserController);


// 5. LISTEN

app.listen(3000, () => {
    console.log('Server is running in port 3000')
})

export default app;