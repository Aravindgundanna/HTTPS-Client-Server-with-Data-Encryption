################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/UART_code/main.c \
../src/UART_code/rs232.c 

OBJS += \
./src/UART_code/main.o \
./src/UART_code/rs232.o 

C_DEPS += \
./src/UART_code/main.d \
./src/UART_code/rs232.d 


# Each subdirectory must supply rules for building sources it contributes
src/UART_code/%.o: ../src/UART_code/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	armv5l-isp20-linux-gnueabi-gcc -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


