import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Transport, MicroserviceOptions } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';
import { Config } from '@eabald/pdf-me-shared';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService: ConfigService<Config> = app.get(ConfigService);
  const user = configService.get('RABBITMQ_USER');
  const password = configService.get('RABBITMQ_PASSWORD');
  const host = configService.get('RABBITMQ_HOST');

  await app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.RMQ,
    options: {
      urls: [`amqp://${user}:${password}@${host}`],
      queue: 'authQueue',
      noAck: false,
      queueOptions: {
        durable: true,
      },
    },
  });
  app.startAllMicroservices();
}
bootstrap();
