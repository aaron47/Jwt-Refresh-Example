import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import * as Joi from 'joi';
import { AuthModule } from './auth/auth.module';
import { AtGuard } from './auth/common/guards';
import { PrismaModule } from './prisma/prisma.module';

@Module({
  imports: [
    AuthModule,
    PrismaModule,
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        DATABASE_URL: Joi.string().required(),
        JWT_SECRET: Joi.string().required(),
        JWT_EXPIRES_IN: Joi.string().required(),
        REFRESH_SECRET: Joi.string().required(),
        REFRESH_EXPIRES_IN: Joi.string().required(),
      }),
    }),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: AtGuard,
    }
  ],

})
export class AppModule {}
