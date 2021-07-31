import { Controller } from '@nestjs/common';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { LoginDto } from './dto/login.dto';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { ConfirmEmailDto } from './dto/confirmEmail.dto';
import { ForgetPasswordDto } from './dto/forgetPassword.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
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

  @MessagePattern({ cmd: 'auth-forget-password' })
  async forgetPassword(@Payload() { email }: ForgetPasswordDto) {
    return this.authenticationService.forgetPassword(email);
  }

  @MessagePattern({ cmd: 'auth-reset-password' })
  async resetPassword(@Payload() { email, password }: ResetPasswordDto) {
    return this.authenticationService.resetPassword(email, password);
  }

  @MessagePattern({ cmd: 'auth-confirm-email' })
  async confirmEmail(@Payload() { email }: ConfirmEmailDto) {
    return this.authenticationService.confirmEmail(email);
  }

  @MessagePattern({ cmd: 'auth-resend-email-confirm' })
  async resendEmailConfirm(@Payload() { email }: ConfirmEmailDto) {
    return this.authenticationService.resendEmailConfirm(email);
  }
}
