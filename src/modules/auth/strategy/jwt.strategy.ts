import { ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { UserEntity } from 'src/modules/users/entities/user.entity';

import { Repository } from 'typeorm';
import { JwtPayload } from '../interfaces/jwt-payload.interface';


export class JwtStrategy extends PassportStrategy(Strategy) {

  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>
  ) {
    super({
      secretOrKey:process.env.JWT_SECRET,
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    });
  }

  async validate(payload: JwtPayload): Promise<UserEntity>{
    const {email} = payload;
    const userJwt = await this.userRepository.findOne({
      where:{email},
      relations:{
        role:true
      }
    });
    
    if(!userJwt){
      throw new UnauthorizedException('Invalid token');
    } else if(!userJwt.isActive){
      throw new ForbiddenException('user is not active');
    } else if(!userJwt.isVerified){
      throw new ForbiddenException('user is not verified');
    }
    return userJwt;
  }
}
