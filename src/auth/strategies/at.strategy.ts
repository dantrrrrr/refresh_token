import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

type JwtPayload = {
  sub: string;
  email: string;
};
@Injectable()
export class AtJwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  //"jwt" is name for Authguard call :AuthGuard("jwt")
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      //   ignoreExpiration: false,
      secretOrKey: 'at-secret',
    });
  }
  validate(payload: JwtPayload) {
    return payload; //req.user =payloadƒ
  }
}
