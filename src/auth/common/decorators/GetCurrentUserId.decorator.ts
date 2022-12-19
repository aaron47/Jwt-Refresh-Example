import { createParamDecorator } from '@nestjs/common';
import { JwtPayload } from 'src/auth/types';

export const GetCurrentUserId = createParamDecorator((_, ctx) => {
  const req = ctx.switchToHttp().getRequest();
  const user = req.user as JwtPayload;
  return user.sub;
});
