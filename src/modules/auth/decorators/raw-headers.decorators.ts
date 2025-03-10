import { createParamDecorator, ExecutionContext } from "@nestjs/common";

export const RawHeaders = createParamDecorator(
    (data: string[], ctx: ExecutionContext)=>{
        const request = ctx.switchToHttp().getRequest();
        const headers =  request.rawHeaders

        return headers
    }
)