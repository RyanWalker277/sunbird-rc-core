import { UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { passportJwtSecret } from 'jwks-rsa';
import { ExtractJwt, Strategy } from 'passport-jwt';

export class JwtStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKeyProvider: passportJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: process.env.JWKS_URI,
      }),
      algorithms: ['RS256'],
    });

    this.logger.log('process.env.JWKS_URI: ' + process.env.JWKS_URI);
  }

  async validate(payload: any) {
    this.logger.log('In validate: ' + JSON.stringify(payload));

    if (!payload) {
      this.logger.error('Invalid payload');
      throw new UnauthorizedException();
    }

    this.logger.log('VALID');
    return { roles: payload.roles };
  }
}