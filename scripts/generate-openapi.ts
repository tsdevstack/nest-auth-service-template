import { generateSwaggerDocs } from '@tsdevstack/nest-common';
import { AppModule } from '../src/app.module';
import { writeFileSync, mkdirSync } from 'fs';

async function generateDocs() {
  // All configuration read automatically from package.json and framework config
  const document = await generateSwaggerDocs(AppModule);

  mkdirSync('./docs', { recursive: true });
  writeFileSync('./docs/openapi.json', JSON.stringify(document, null, 2));
  console.log('✅ OpenAPI spec generated at ./docs/openapi.json');
}

generateDocs().catch((error) => {
  console.error('❌ Failed to generate OpenAPI docs:', error);
  process.exit(1);
});
