import 'reflect-metadata';
import { AppModule } from './app.module';
import { startApp } from '@tsdevstack/nest-common';

async function bootstrap() {
  await startApp(AppModule);
}

bootstrap().catch((error) => {
  console.error('FATAL ERROR:', error);
  process.exit(1);
});
