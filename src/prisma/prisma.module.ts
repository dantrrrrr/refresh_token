import { Global, Module } from '@nestjs/common';
import { PrismaService } from './prisma.service';
@Global() //allow others module can access
@Module({
  providers: [PrismaService],
  exports: [PrismaService],
})
export class PrismaModule {}
