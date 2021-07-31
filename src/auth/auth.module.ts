import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ClientProxyFactory, Transport } from '@nestjs/microservices';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    ConfigModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get('JWT_SECRET'),
        signOptions: {
          expiresIn: `${configService.get('JWT_EXPIRATION_TIME')}s`,
        },
      }),
    }),
  ],
  providers: [
    AuthService,
    {
      provide: 'USERS_SERVICE',
      useFactory: (configService: ConfigService) => {
        const user = configService.get('RABBITMQ_USER');
        const password = configService.get('RABBITMQ_PASSWORD');
        const host = configService.get('RABBITMQ_HOST');
        const queueName = configService.get('RABBITMQ_QUEUE_NAME');

        return ClientProxyFactory.create({
          transport: Transport.RMQ,
          options: {
            urls: [`amqp://${user}:${password}@${host}`],
            queue: queueName,
            queueOptions: {
              durable: true,
            },
          },
        });
      },
      inject: [ConfigService],
    },
    // {
    //   provide: 'EMAILS_SERVICE',
    //   useFactory: (configService: ConfigService) => {
    //     const user = configService.get('RABBITMQ_USER');
    //     const password = configService.get('RABBITMQ_PASSWORD');
    //     const host = configService.get('RABBITMQ_HOST');
    //     const queueName = configService.get('RABBITMQ_QUEUE_NAME');

    //     return ClientProxyFactory.create({
    //       transport: Transport.RMQ,
    //       options: {
    //         urls: [`amqp://${user}:${password}@${host}`],
    //         queue: queueName,
    //         queueOptions: {
    //           durable: true,
    //         },
    //       },
    //     });
    //   },
    //   inject: [ConfigService],
    // },
  ],
  controllers: [AuthController],
})
export class AuthModule {}
