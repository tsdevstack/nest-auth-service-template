import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Patch,
  Post,
  Query,
  Req,
  UseGuards,
  Version,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiBody,
  ApiConflictResponse,
  ApiForbiddenResponse,
  ApiNotFoundResponse,
  ApiOperation,
  ApiResponse,
  ApiServiceUnavailableResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import {
  RateLimitDecorator,
  RateLimitGuard,
  Roles,
} from '@tsdevstack/nest-common';
import type { AuthenticatedRequest } from '@tsdevstack/nest-common';
import { ActiveAdminGuard } from '../admin/active-admin.guard';
import { ApiKeysService } from './api-keys.service';
import { ApiKeyDto } from './dto/api-key.dto';
import { ApiKeyUsageDto } from './dto/api-key-usage.dto';
import { CreateApiKeyDto } from './dto/create-api-key.dto';
import { CreatedApiKeyDto } from './dto/created-api-key.dto';
import { ListApiKeysQueryDto } from './dto/list-api-keys-query.dto';
import { RotateApiKeyDto } from './dto/rotate-api-key.dto';
import { RotatedApiKeyDto } from './dto/rotated-api-key.dto';
import { UpdateApiKeyDto } from './dto/update-api-key.dto';

const UNAUTHORIZED =
  'Authentication required - invalid or missing access token';
const FORBIDDEN = 'Caller is not an active admin';
const INDEX_UNAVAILABLE = 'Redis unavailable; nothing was changed';

/**
 * Admin-only API key management. Keys belong to a named consumer, not to a
 * user; they are validated by Kong against the Redis index this service
 * maintains, and changes take effect on the next request.
 *
 * Guards run in this order: `RolesGuard` (from `@Roles('ADMIN')`, checks the
 * role in the JWT, no I/O), `RateLimitGuard`, then `ActiveAdminGuard`
 * (re-checks the caller's current role and status in the database). Class
 * decorators apply bottom-up and each `@UseGuards()` appends, so
 * `@UseGuards()` must stay above `@Roles()` for this order.
 */
@Controller('admin/api-keys')
@ApiTags('admin')
@ApiBearerAuth()
@UseGuards(RateLimitGuard, ActiveAdminGuard)
@Roles('ADMIN')
@RateLimitDecorator({
  keyGenerator: 'userId',
  maxRequests: 1000,
  windowMs: 60 * 60 * 1000,
})
export class AdminApiKeysController {
  constructor(private readonly apiKeysService: ApiKeysService) {}

  @Get()
  @Version('1')
  @ApiOperation({
    operationId: 'adminListApiKeys',
    summary: 'List API keys (admin)',
    description:
      'Lists API keys, newest first, optionally for one consumer. Requires the ADMIN system role.',
  })
  @ApiResponse({ status: 200, description: 'API keys', type: [ApiKeyDto] })
  @ApiBadRequestResponse({ description: 'Invalid consumer filter' })
  @ApiUnauthorizedResponse({ description: UNAUTHORIZED })
  @ApiForbiddenResponse({ description: FORBIDDEN })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async list(@Query() query: ListApiKeysQueryDto): Promise<ApiKeyDto[]> {
    return await this.apiKeysService.list(query.consumer);
  }

  @Post()
  @Version('1')
  @ApiOperation({
    operationId: 'adminCreateApiKey',
    summary: 'Create an API key (admin)',
    description:
      'Creates a key for a named consumer. The response contains the key itself; it is shown only once. Limits left out use the gateway defaults. Requires the ADMIN system role.',
  })
  @ApiBody({ type: CreateApiKeyDto, description: 'Key settings' })
  @ApiResponse({
    status: 201,
    description: 'Key created (the key is shown once)',
    type: () => CreatedApiKeyDto,
  })
  @ApiBadRequestResponse({
    description: 'Invalid consumer name, limit or expiry',
  })
  @ApiUnauthorizedResponse({ description: UNAUTHORIZED })
  @ApiForbiddenResponse({ description: FORBIDDEN })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @ApiServiceUnavailableResponse({ description: INDEX_UNAVAILABLE })
  async create(
    @Req() req: AuthenticatedRequest,
    @Body() body: CreateApiKeyDto,
  ): Promise<CreatedApiKeyDto> {
    return await this.apiKeysService.create(req.user?.id ?? '', body);
  }

  @Get(':id')
  @Version('1')
  @ApiOperation({
    operationId: 'adminGetApiKey',
    summary: 'Get an API key (admin)',
    description:
      'Returns one key (never the key itself). Requires the ADMIN system role.',
  })
  @ApiResponse({ status: 200, description: 'API key', type: () => ApiKeyDto })
  @ApiUnauthorizedResponse({ description: UNAUTHORIZED })
  @ApiForbiddenResponse({ description: FORBIDDEN })
  @ApiNotFoundResponse({ description: 'API key not found' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async get(@Param('id') id: string): Promise<ApiKeyDto> {
    return await this.apiKeysService.get(id);
  }

  @Patch(':id')
  @Version('1')
  @ApiOperation({
    operationId: 'adminUpdateApiKey',
    summary: 'Update an API key (admin)',
    description:
      'Changes the name, limits or expiry of a key. Absent fields stay; null removes a limit or the expiry. Effective at the gateway on the next request. Requires the ADMIN system role.',
  })
  @ApiBody({ type: UpdateApiKeyDto, description: 'Changes' })
  @ApiResponse({
    status: 200,
    description: 'Key updated',
    type: () => ApiKeyDto,
  })
  @ApiBadRequestResponse({ description: 'Invalid limit or expiry' })
  @ApiUnauthorizedResponse({ description: UNAUTHORIZED })
  @ApiForbiddenResponse({ description: FORBIDDEN })
  @ApiNotFoundResponse({ description: 'API key not found' })
  @ApiConflictResponse({ description: 'The key is revoked' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @ApiServiceUnavailableResponse({ description: INDEX_UNAVAILABLE })
  async update(
    @Param('id') id: string,
    @Body() body: UpdateApiKeyDto,
  ): Promise<ApiKeyDto> {
    return await this.apiKeysService.update(id, body);
  }

  @Post(':id/revoke')
  @Version('1')
  @HttpCode(200)
  @ApiOperation({
    operationId: 'adminRevokeApiKey',
    summary: 'Revoke an API key (admin)',
    description:
      'Revokes a key: the gateway rejects it from the next request on (401 api_key_revoked). Revoking a revoked key changes nothing. Requires the ADMIN system role.',
  })
  @ApiResponse({
    status: 200,
    description: 'Key revoked',
    type: () => ApiKeyDto,
  })
  @ApiUnauthorizedResponse({ description: UNAUTHORIZED })
  @ApiForbiddenResponse({ description: FORBIDDEN })
  @ApiNotFoundResponse({ description: 'API key not found' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @ApiServiceUnavailableResponse({ description: INDEX_UNAVAILABLE })
  async revoke(@Param('id') id: string): Promise<ApiKeyDto> {
    return await this.apiKeysService.revoke(id);
  }

  @Post(':id/rotate')
  @Version('1')
  @ApiOperation({
    operationId: 'adminRotateApiKey',
    summary: 'Rotate an API key (admin)',
    description:
      'Issues a replacement key with the same consumer, name, limits and expiry (shown once), and shortens the old key to the earlier of its expiry and now plus the grace (default 7 days). Both work during the grace. Requires the ADMIN system role.',
  })
  @ApiBody({
    type: RotateApiKeyDto,
    description: 'Grace period',
    required: false,
  })
  @ApiResponse({
    status: 201,
    description: 'Replacement key created (shown once)',
    type: () => RotatedApiKeyDto,
  })
  @ApiBadRequestResponse({ description: 'Invalid grace period' })
  @ApiUnauthorizedResponse({ description: UNAUTHORIZED })
  @ApiForbiddenResponse({ description: FORBIDDEN })
  @ApiNotFoundResponse({ description: 'API key not found' })
  @ApiConflictResponse({ description: 'The key is revoked or expired' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  @ApiServiceUnavailableResponse({ description: INDEX_UNAVAILABLE })
  async rotate(
    @Req() req: AuthenticatedRequest,
    @Param('id') id: string,
    @Body() body: RotateApiKeyDto,
  ): Promise<RotatedApiKeyDto> {
    return await this.apiKeysService.rotate(
      req.user?.id ?? '',
      id,
      body?.graceHours,
    );
  }

  @Get(':id/usage')
  @Version('1')
  @ApiOperation({
    operationId: 'adminGetApiKeyUsage',
    summary: 'Saved usage of an API key (admin)',
    description:
      'Week and month request totals saved by the usage sync job, newest first. Requires the ADMIN system role.',
  })
  @ApiResponse({
    status: 200,
    description: 'Usage per period',
    type: [ApiKeyUsageDto],
  })
  @ApiUnauthorizedResponse({ description: UNAUTHORIZED })
  @ApiForbiddenResponse({ description: FORBIDDEN })
  @ApiNotFoundResponse({ description: 'API key not found' })
  @ApiResponse({ status: 429, description: 'Rate limit exceeded' })
  async usage(@Param('id') id: string): Promise<ApiKeyUsageDto[]> {
    return await this.apiKeysService.usage(id);
  }
}
