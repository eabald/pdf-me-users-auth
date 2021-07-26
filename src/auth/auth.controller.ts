import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { LoginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authenticationService: AuthService) {}

  @MessagePattern({ cmd: 'auth-register' })
  async register(@Payload() payload: RegisterDto) {
    return this.authenticationService.register(payload);
  }

  @MessagePattern({ cmd: 'auth-get-authenticated-user' })
  async getAuthenticatedUser(@Payload() payload: LoginDto) {
    return this.authenticationService.getAuthenticatedUser(
      payload.email,
      payload.password,
    );
  }
}
