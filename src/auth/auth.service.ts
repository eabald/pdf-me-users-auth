import { Injectable, Inject, HttpStatus } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { ClientProxy, RpcException } from '@nestjs/microservices';
import { RegisterDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(@Inject('USERS_SERVICE') private usersService: ClientProxy) {}

  public async register(registrationData: RegisterDto) {
    const hashedPassword = await bcrypt.hash(registrationData.password, 10);
    try {
      return this.usersService
        .send(
          { cmd: 'users-create' },
          {
            ...registrationData,
            password: hashedPassword,
          },
        )
        .toPromise();
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
}
