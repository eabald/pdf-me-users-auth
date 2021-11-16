import { Injectable, Inject, HttpStatus } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { JwtService } from '@nestjs/jwt';
import {
  TokenPayload,
  RegisterDto,
  ApiKeyPayload,
} from '@eabald/pdf-me-shared';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    @Inject('USERS_SERVICE') private usersService: ClientProxy,
    @Inject('EMAILS_SERVICE') private emailsService: ClientProxy,
    @Inject('PAYMENTS_SERVICE') private paymentsService: ClientProxy,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  public async register(registrationData: RegisterDto) {
    const hashedPassword = await bcrypt.hash(registrationData.password, 10);
    try {
      const stripeCustomer = await this.paymentsService
        .send(
          { cmd: 'payments-create-customer' },
          { name: registrationData.name, email: registrationData.email },
        )
        .toPromise();
      const user = await this.usersService
        .send(
          { cmd: 'users-create' },
          {
            ...registrationData,
            password: hashedPassword,
            stripeCustomerId: stripeCustomer.id,
          },
        )
        .toPromise();
      const token = await this.generateToken(user.id);
      await this.emailsService
        .send(
          { cmd: 'emails-send-confirm-email' },
          { email: user.email, token },
        )
        .toPromise();
      return user;
    } catch (error) {
      throw new RpcException(error);
    }
  }

  public async getAuthenticatedUser(email: string, plainTextPassword: string) {
    try {
      const user = await this.usersService
        .send({ cmd: 'users-get-by-email' }, email)
        .toPromise();
      await this.verifyPassword(plainTextPassword, user.password);
      user.password = undefined;
      return user;
    } catch (error) {
      throw new RpcException({
        message: 'Wrong credentials provided',
        statusCode: HttpStatus.BAD_REQUEST,
      });
    }
  }

  private async verifyPassword(
    plainTextPassword: string,
    hashedPassword: string,
  ) {
    const isPasswordMatching = await bcrypt.compare(
      plainTextPassword,
      hashedPassword,
    );
    if (!isPasswordMatching) {
      throw new RpcException({
        message: 'Wrong credentials provided',
        statusCode: HttpStatus.BAD_REQUEST,
      });
    }
  }

  public async forgetPassword(email: string) {
    try {
      const user = await this.usersService
        .send({ cmd: 'users-get-by-email' }, email)
        .toPromise();
      const token = await this.generateToken(user.id);
      await this.emailsService.send(
        { cmd: 'emails-send-reset-password' },
        token,
      );
      return await this.usersService.send(
        { cmd: 'users-set-resetting-password' },
        email,
      );
    } catch (error) {
      throw new RpcException({
        message: 'Wrong credentials provided',
        statusCode: HttpStatus.BAD_REQUEST,
      });
    }
  }

  public async resetPassword(email: string, password: string) {
    const hashedPassword = await bcrypt.hash(password, 10);
    return await this.usersService.send(
      { cmd: 'users-update-password' },
      { email, password: hashedPassword },
    );
  }

  public async confirmEmail(email: string) {
    return await this.usersService.send({ cmd: 'users-confirm-email' }, email);
  }

  public async resendEmailConfirm(email: string) {
    const user = await this.usersService
      .send({ cmd: 'users-get-by-email' }, email)
      .toPromise();
    if (!user.isEmailConfirmed) {
      const token = await this.generateToken(user.id);
      return this.emailsService.send(
        { cmd: 'emails-send-confirm-email' },
        { email, token },
      );
    }
  }

  private generateToken(userId: number) {
    const payload: TokenPayload = { userId };
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_SECRET'),
      expiresIn: `${this.configService.get('JWT_EXPIRATION_TIME')}s`,
    });
    return token;
  }

  async validateApiKey(key: string) {
    try {
      const keyData: ApiKeyPayload = this.jwtService.verify(
        key,
        this.configService.get('JWT_SECRET'),
      );
      const user = await this.usersService
        .send({ cmd: 'users-get-by-id' }, keyData.userId)
        .toPromise();
      if (!user || user.key !== keyData.key) {
        return false;
      }
      return user;
    } catch (error) {
      return false;
    }
  }

  generateKey() {
    const totalBytes = 512;
    let apiKey;
    apiKey = randomBytes(totalBytes).toString('hex');
    const endIndex = apiKey.length - (apiKey.length - 512);
    apiKey = apiKey.slice(0, endIndex);
    return apiKey;
  }

  async generateApiKey(userId: number) {
    const key = this.generateKey();
    await this.usersService
      .send({ cmd: 'users-save-api-key' }, { userId, key })
      .toPromise();
    const payload: ApiKeyPayload = { userId, key };
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_SECRET'),
      expiresIn: `${365 * 24 * 3600}s`,
    });
    return token;
  }
}
