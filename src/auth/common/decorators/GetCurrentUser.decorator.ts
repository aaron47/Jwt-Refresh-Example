import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayloadWithRt } from 'src/auth/types';

export const GetCurrentUser = createParamDecorator(
  (data: keyof JwtPayloadWithRt | undefined, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest();

    if (!data) return req.user;

    return req.user[data];
  },
);
