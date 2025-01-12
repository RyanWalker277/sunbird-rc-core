import {
  Body,
  CacheInterceptor,
  CACHE_MANAGER,
  Controller,
  Get,
  Inject,
  Param,
  Patch,
  Post,
  Query,
  UseInterceptors,
  Put,
} from '@nestjs/common';
import {
  ApiBadRequestResponse,
  ApiBody,
  ApiCreatedResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiOperation,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { VerifiableCredentialSchema } from '@prisma/client';
import { Cache } from 'cache-manager';

import { VCSModelSchemaInterface } from 'src/types/VCModelSchema.interface';
import { CreateCredentialDTO } from './dto/create-credentials.dto';
import { VCItem } from './entities/VCItem.entity';
import { VCModelSchema } from './entities/VCModelSchema.entity';
import { SchemaService } from './schema.service';

@Controller('credential-schema')
@UseInterceptors(CacheInterceptor)
export class SchemaController {
  constructor(
    private readonly schemaService: SchemaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  // TODO: Add role based guards here
  @Get(':id')
  @ApiQuery({ name: 'id', required: true, type: String })
  @ApiOperation({ summary: 'Get a Verifiable Credential Schema by id (did)' })
  @ApiOkResponse({
    status: 200,
    description: 'The record has been successfully created.',
    type: VCItem,
  })
  @ApiNotFoundResponse({
    status: 404,
    description: 'The record has not been found.',
  })
  getCredentialSchema(@Param('id') id) {
    console.log('id: ', id);
    return this.schemaService.getCredentialSchema({ id });
  }

  @Get()
  @ApiQuery({ name: 'id', required: true, type: String })
  @ApiOperation({ summary: 'Get a Verifiable Credential Schema by id (did)' })
  @ApiOkResponse({
    status: 200,
    description: 'The record has been successfully created.',
    type: VCItem,
  })
  @ApiNotFoundResponse({
    status: 404,
    description: 'The record has not been found.',
  })
  getCredentialSchemaByTags(
    @Query('tags') tags: string,
    @Query('page') page: string,
    @Query('limit') limit: string,
  ) {
    console.log('tags: ', tags);
    console.log('typeof tags: ', typeof tags);
    // console.log(tags instanceof Array);
    return this.schemaService.getSchemaByTags(
      tags.split(','),
      isNaN(parseInt(page, 10)) ? 1 : parseInt(page, 10),
      isNaN(parseInt(limit, 10)) ? 10 : parseInt(limit, 10),
    );
  }

  // TODO: Add role based guards here
  @Post()
  @ApiOperation({ summary: 'Create a new Verifiable Credential Schema' })
  @ApiBody({
    type: VCModelSchema,
  })
  @ApiCreatedResponse({
    status: 201,
    description: 'The record has been successfully created.',
    type: VCItem,
  })
  @ApiBadRequestResponse({
    status: 400,
    description: 'There was some problem with the request.',
  })
  createCredentialSchema(
    @Body() body: CreateCredentialDTO, //: Promise<VerifiableCredentialSchema>
  ) {
    console.log(body);
    return this.schemaService.createCredentialSchema(body);
  }

  // TODO: Add role based guards here
  @Put(':id')
  @ApiQuery({ name: 'id', required: true, type: String })
  @ApiBody({
    type: VCModelSchema,
  })
  @ApiOperation({
    summary: 'Update a Verifiable Credential Schema by id (did)',
  })
  @ApiOkResponse({
    status: 200,
    description: 'The record has been successfully updated.',
    type: VCItem,
  })
  @ApiNotFoundResponse({
    status: 404,
    description:
      'The record with the passed query param id has not been found.',
  })
  @ApiBadRequestResponse({
    status: 400,
    description: 'There was some prioblem with the request.',
  })
  updateCredentialSchema(@Param('id') id, @Body() data: CreateCredentialDTO) {
    // console.log('id: ', query.id);
    // delete data['id'];
    return this.schemaService.updateCredentialSchema({
      where: { id: id },
      data,
    });
  }
}
