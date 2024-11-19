clc;clear
original_picture=imread('C:\Users\gaiya\Desktop\測試圖片\lena_gray_512.tif');
%original_picture=rgb2gray(original_picture);%把RGB图像转化成灰度图像
original_picture=original_picture(:,:,1); 
[X,Y,O] = size(original_picture);%M個row，N個column
figure(1)
subplot(2,2,1);
%{
m=ceil(mod(X,8));
n=ceil(mod(Y,8));
if  m==0
    GrayPic_m=[GrayPic;zeros(8,Y)];% row整除8，補8排0
    GrayPic_m(X+8-m,1)=8;% 在左下角給8
else
    GrayPic_m=[GrayPic;zeros(8-m,Y)];% row除8餘數，補0
    GrayPic_m(X+8-m,1)=8-m;% 在左下角給8-m
end
if  n==0
     GrayPic_n=[GrayPic_m,zeros(X+8-m,8)];%column同理
     GrayPic_n(X+8-m,Y+8-n)=8;
else
    GrayPic_n=[GrayPic_m,zeros(X+8-m,8-n)];
    GrayPic_n(X+8-m,Y+8-n)=8-n;
end
%}
[M,N,O] = size( original_picture);%重新計算補零後的M,N大小
imshow(original_picture);
figure(1)
subplot(2,2,3);
imhist(original_picture);%原始图像的灰度图像的直方图
tic
sha=hash(original_picture,'SHA-256');
%%
%chaotic system
a=36;b=3;c=28;d=-16;k=0.2;
IC1=bin2dec(sha(73:109))*10^-12; IC2=bin2dec(sha(110:146))*10^-12;  IC3=bin2dec(sha(147:183))*10^-12; IC4=bin2dec(sha(184:220))*10^-12;
initial_C=[IC1 IC2 IC3 IC4];

f = @(t,x) [a*(x(2)-x(1));-x(1)*x(3)+d*x(1)+c*x(2)-x(4);x(1)*x(2)-b*x(3);x(1)+k];
ts=11800;
span=[0,ts];
[t,xa]=ode45(@(t,x)f(t,x),span,initial_C);
xaa=floor(mod((abs(xa) - floor(abs(xa)))*10^14,256));
xaaa=xaa(1000:end,:);%濾掉前1000個暫態
key=xaaa.';
key=key(1:M*N/64*48*4);
keys=reshape(key,M*N/64*48*4/(N/8),N/8);%reshape成區塊竪著排列
keys=uint8(keys);
%%

initial_key5 = bin2dec(sha(1:36))*10^-11
row_number = [];
while numel(row_number)<M
    initial_key5 = 4*initial_key5*(1 - initial_key5);
    l = floor(mod(initial_key5*10^14,M));
    if ismember(l,row_number)
       
    else
        row_number=[row_number;l];%row的新位置
    end
end
row=[];
for i = 1:M
   row=[row;original_picture(row_number(i)+1,:)];%row重排列
end
figure(2)
subplot(2,2,1);
imhist(row);
initial_key6 = bin2dec(sha(37:72))*10^-11;
column_number = [];
while numel(column_number)<N
    initial_key6 = 4*initial_key6*(1 - initial_key6);
    e = floor(mod(initial_key6*10^14,N));
    if ismember(e,column_number)
       
    else
        column_number=[column_number;e];%New shuffling locations

    end
end

mess=[];
mess = dec2base(row,2,8);%Binary conversion 

 column=[];
for i = 1:N
    column=[ column;mess(M*(column_number(i)+1)-M+1:M*(column_number(i)+1),1:4)];%column重排
end

total_shuffling_char=[column mess(1:end,5:8)];%Combination of L,R two parts
total_shuffling=bin2dec(total_shuffling_char);%Decimal conversion  
total_shuffling_uint8=uint8(total_shuffling);%Uint8 conversion 
P_reshape=reshape(total_shuffling_uint8,M,N);
figure(2)
subplot(2,2,2);
imhist(P_reshape);
P=[]
for i=1:8
   P=[P;P_reshape(:,N/8*i-N/8+1:N/8*i)];%區塊竪著排放，對下面的DES結構索引比較方便。
end
%%

% IP
IP_table = [58, 50, 42, 34, 26, 18, 10, 2,60, 52, 44, 36, 28, 20, 12, 4,62, 54, 46, 38, 30, 22, 14, 6,64, 56, 48, 40, 32, 24, 16, 8,57, 49, 41, 33, 25, 17, 9, 1,59, 51, 43, 35, 27, 19, 11, 3,61, 53, 45, 37, 29, 21, 13, 5,63, 55, 47, 39, 31, 23, 15, 7];  % IP置换表
ciphertext_ip=[];
for i = 1:64
    ciphertext_ip=[ciphertext_ip;P(M/8*IP_table(i)-M/8+1:M/8*IP_table(i),:)];
end
%%

Limage=ciphertext_ip(1:M/8*64/2,:);
Rimage=ciphertext_ip(M/8*64/2+1:end,:);
ex_tab = [32, 1, 2, 3, 4, 5,4, 5, 6, 7, 8, 9,8, 9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32, 1];   % E扩展表
Pbox=[16, 7,20,21,29,12,28,17,1,15,23,26, 5,18,31,10,2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25];  % IP置换表     ]
initial_key7 = bin2dec(sha(221:256))*10^-11;
s_box_diedie=[]
for i=1:4
    E_BOX=[];
    s_box=[]
    p_box=[]
    s_box_location=[]
    NextL = Rimage;          % 下一轮的L是上一轮的R
    now_key = keys(M/8*48*i-M/8*48+1:M/8*48*i,:);       % 这一轮加密的密钥

    for j=1:48
        E_BOX=[E_BOX;Rimage(M/8*ex_tab(j)-M/8+1:M/8*ex_tab(j),:)];
    end
    Rtext_E=bitxor(E_BOX,now_key);  % 与密钥异或处理

     while numel(s_box_location)<32
        initial_key7 = 4*initial_key7*(1 - initial_key7);
        g = floor(mod(initial_key7*10^14,48));
        if ismember(g,s_box_location)

        else
            s_box_location=[s_box_location;g];
        end
     end
   s_box_diedie=[s_box_diedie;s_box_location];
   for k = 1:32
         s_box=[ s_box;Rtext_E( (s_box_location(k)+1)*M/8-M/8+1:M/8*(s_box_location(k)+1),:)];
   end

    for l=1:32
        p_box=[p_box; s_box(M/8*Pbox(l)-M/8+1:M/8*Pbox(l),:)];
    end
    Rimage=bitxor( p_box,Limage);  % 与上一轮L异或处理

    Limage = NextL;
end
Cipherimage = [Rimage;Limage];%左右合起來
% 对最终结果进行IP逆置换
IP_table_reverse = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58 26,33,1,41, 9,49,17,57,25,];% IP置换表
Cipherimage_ip=[]
for i=1:64
    Cipherimage_ip=[Cipherimage_ip;Cipherimage(M/8*IP_table_reverse(i)-M/8+1:M/8*IP_table_reverse(i),:)];
end
Cipheredimage=[]
for i=1:8
   Cipheredimage=[Cipheredimage,Cipherimage_ip(i*M-M+1:M*i,:)];
end
toc
figure(1)
subplot(2,2,2);
imshow(Cipheredimage);
figure(1)
subplot(2,2,4);
imhist(Cipheredimage);
imwrite(Cipheredimage,'Cipheredimage.png')
imwrite(original_picture,'Plainimage.png')
%%
entropy=entropy(Cipheredimage);
%r1=cov(original_picture,10000);
%r2=cov(Cipheredimage,10000);
NPCR=NPCR_UACI(original_picture,Cipheredimage);
