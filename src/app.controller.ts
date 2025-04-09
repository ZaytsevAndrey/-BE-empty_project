import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiOperation, ApiResponse } from '@nestjs/swagger';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @ApiOperation({ summary: 'Get Hello message' })
  @ApiResponse({ status: 200, description: 'Returns a hello message' })
  @Get()
  getHello(): string {
    return this.appService.getHello();
  }
}
