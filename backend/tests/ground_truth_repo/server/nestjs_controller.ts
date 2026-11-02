import { Controller, Get, Post, Param, Query, Body, UseGuards } from '@nestjs/common';

@Controller('api/nest/billing')
export class BillingController {
  @Get('invoices')
  getInvoices(@Query('account_id') accountId: string) {
    return [{ id: 'inv_1', accountId }];
  }

  @Post('invoices')
  createInvoice(@Body() invoiceDto: CreateInvoiceDto) {
    return invoiceDto;
  }
}
