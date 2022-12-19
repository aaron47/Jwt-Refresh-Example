import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon2 from 'argon2';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async signUpLocal(dto: AuthDto): Promise<Tokens> {
    const { email, password } = dto;
    const hash = await this.hashData(password);
    const newUser = await this.prisma.user.create({
      data: {
        email,
        hash,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateRtHash(newUser.id, tokens.refresh_token);

    return tokens;
  }

  async signInLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) throw new ForbiddenException('Invalid Credentials');

    const isPasswordValid = await argon2.verify(user.hash, dto.password);

    if (!isPasswordValid) throw new ForbiddenException('Invalid Credentials');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: string): Promise<void> {
    await this.prisma.user.updateMany({
      where: { id: parseInt(userId), hashedRt: { not: null } },
      data: { hashedRt: null },
    });
  }

  async refreshTokens(userId: string, rt: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: { id: parseInt(userId) },
    });

    if (!user || !user.hashedRt) throw new ForbiddenException('Access Denied');

    const isRtValid = await argon2.verify(user.hashedRt, rt);

    if (!isRtValid) throw new ForbiddenException('Bad Refresh Token');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  private async hashData(data: string) {
    return argon2.hash(data);
  }

  private async getTokens(userId: number, email: string): Promise<Tokens> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: this.configService.get<string>('JWT_SECRET'),
          expiresIn: this.configService.get<string>('JWT_EXPIRES_IN'),
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, email },
        {
          secret: this.configService.get<string>('REFRESH_SECRET'),
          expiresIn: this.configService.get<string>('REFRESH_EXPIRES_IN'),
        },
      ),
    ]);

    return {
      access_token,
      refresh_token,
    };
  }

  private async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: hash },
    });
  }
}
