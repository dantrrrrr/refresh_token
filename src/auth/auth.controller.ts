import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
  Req,
  Logger,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AtGuard, RtGuard } from 'src/common/guards';
import { GetCurrentUser, GetCurrentUserId } from 'src/common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  private readonly logger = new Logger(AuthController.name);
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signupLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(dto);
  }

  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signinLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(dto);
  }

  @UseGuards(AtGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUserId() userId: number) {
    this.logger.log(`User ${userId} is logging out`);
    // console.log(
    //   '🚀 ~ file: auth.controller.ts:37 ~ AuthController ~ logout ~ user:',
    //   user,
    // );
    return this.authService.logout(userId);
  }

  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(
    @GetCurrentUserId() userId: number,
    // @GetCurrentUser('refreshToken') refreshToken: string,

    @GetCurrentUser('refreshToken') refreshToken: string,
  ) {
    console.log(
      '🚀 ~ file: auth.controller.ts:56 ~ AuthController ~ refreshToken:',
      refreshToken,
    );
    console.log(
      '🚀 ~ file: auth.controller.ts:62 ~ AuthController ~ userId:',
      userId,
    );

    return this.authService.refreshTokens(userId, refreshToken);
    // return this.authService.refreshTokens(userId, refreshToken);
  }
}
