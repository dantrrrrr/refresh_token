import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { ExtractJwt, Strategy } from 'passport-jwt';
@Injectable()
export class RtJwtStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      //   ignoreExpiration: false,
      secretOrKey: 'rt-secret',

      passReqToCallback: true, //pass the object to callback function below
    });
  }
  //payload data after  decoded jwt token (above)
  validate(req: Request, payload: any) {
    const refreshToken = req.get('authorization').replace('Bearer', ' ').trim();
    return { ...payload, refreshToken }; //req.user =payloadƒ
  }
}
