import jwt from 'jsonwebtoken'

export const auth = (request,response, next)=>{
    const token = request.header("Authorization");
    jwt.verify(token,process.env.JWT_SECRET)
    next();
}