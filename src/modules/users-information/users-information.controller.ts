import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { UsersInformationService } from './users-information.service';
import { CreateUsersInformationDto } from './dto/create-users-information.dto';

@Controller('users-information')
export class UsersInformationController {
  constructor(private readonly usersInformationService: UsersInformationService) {}

  //TODO: CONTROLLER USERS INFORMATION
  @Post()
  create(@Body() createUsersInformationDto: CreateUsersInformationDto) {
    return this.usersInformationService.create(createUsersInformationDto);
  }

  @Get()
  findAll() {
    return this.usersInformationService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersInformationService.findOne(+id);
  }


  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersInformationService.remove(+id);
  }
}
