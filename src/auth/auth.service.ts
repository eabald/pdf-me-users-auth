import { Injectable, Inject, HttpStatus } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { RegisterDto } from './dto/register.dto';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from './interfaces/tokenPayload.interface';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    @Inject('USERS_SERVICE') private usersService: ClientProxy,
    // @Inject('EMAILS_SERVICE') private emailsService: ClientProxy,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  public async register(registrationData: RegisterDto) {
    const hashedPassword = await bcrypt.hash(registrationData.password, 10);
    try {
      const user = await this.usersService
        .send(
          { cmd: 'users-create' },
          {
            ...registrationData,
            password: hashedPassword,
          },
        )
        .toPromise();
      const token = this.generateToken(user.id);
      // await this.emailsService({ 'emails-send-reset-password' }, token);
      console.log(token);
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
      const token = this.generateToken(user.id);
      // send email with token
      // await this.emailsService({ 'emails-send-reset-password' }, token);
      console.log(token);
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
      const token = this.generateToken(user.id);
      // return this.emailService.send(
      //   { cmd: 'emails-send-confirm-email' },
      //   { email, token },
      // );
      console.log(token);
      return true;
    }
  }

  private generateToken(userId: number) {
    const payload: TokenPayload = { userId };
    const token = this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: `${this.configService.get(
        'JWT_ACCESS_TOKEN_EXPIRATION_TIME',
      )}s`,
    });
    return token;
  }
}
