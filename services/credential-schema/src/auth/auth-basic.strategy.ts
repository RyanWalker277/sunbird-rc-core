import { BasicStrategy as Strategy } from 'passport-http';
import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';

@Injectable()
export class BasicStrategy extends PassportStrategy(Strategy) {
  private readonly logger = new Logger(BasicStrategy.name);
  constructor() {
    super({
      passReqToCallback: true,
    });
  }

  public validate = async (req, username, password): Promise<boolean> => {
    this.logger.log('Validating credentials: ' + username);

    if (
      process.env.HTTP_BASIC_USER === username &&
      process.env.HTTP_BASIC_PASS === password
    ) {
      this.logger.log('Credentials are valid: ' + username);
      return true;
    }

    this.logger.error('Invalid credentials: ' + username);
    throw new UnauthorizedException();
  };
}