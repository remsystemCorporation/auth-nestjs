import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { UserEntity } from './entities/user.entity';
import { Repository } from 'typeorm';
import { PaginationDto } from '../common/dto/pagination.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>
  ) { }

  async findAllUser(paginationDto:PaginationDto): Promise<{ users: UserEntity[]; total: number }> {
    const { limit = 10, page = 1 } = paginationDto;

    const [users, total] = await this.userRepository.findAndCount({
      take: limit,
      skip: (page - 1) * limit,
      relations:{
        userInformation: true,
      }
    });

    return {
      users,
      total,
    };
  }


  async updateProfilePicture(userId: number, imageUrl: string) {
    const user = await this.userRepository.findOne({ where: { idUser: userId } });
    if (!user) throw new Error('User not found');
    if (user.idUser !== userId) throw new Error('User not authorized to update this profile picture');

    await this.userRepository.update(userId, { profilePicture: imageUrl });

    return {
      message: 'Profile picture updated successfully',
      imageUrl,
    }
  }

}
