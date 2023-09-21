import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';

import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { Prisma } from '@prisma/client';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signupLocal(dto: AuthDto): Promise<Tokens> {
    try {
      //hash password
      const hash = await this.hashData(dto.password);
      //add new user with hash password
      const newUser = await this.prisma.user.create({
        data: { email: dto.email, hash },
      });
      const tokens = await this.getTokens(newUser.id, newUser.email);
      await this.updateRtHash(newUser.id, tokens.refresh_token);
      return tokens;
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException('A user with this email already exit.');
      }
      throw error;
    }
  }
  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });
    if (!user) {
      throw new BadRequestException('Invalid credentials');
    }
    //check pass
    const passwordValid = await bcrypt.compare(dto.password, user.hash);
    if (!passwordValid) {
      throw new BadRequestException('Invalid credentials');
    }
    //password is correct
    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }
  logout() {
    return 'ok';
  }
  refreshTokens() {
    return 'ok';
  }
  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }
  async getTokens(userId: number, email: string) {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          email: email,
        },
        { secret: 'at-secret', expiresIn: 60 * 15 },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          email: email,
        },
        { secret: 'rt-secret', expiresIn: '7d' },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
  async updateRtHash(userId: number, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: hash },
    });
  }
}
