clc;clear
image_1=imread('C:\Users\gaiya\Desktop\論文matlab\Cipheredimage.png');
image_1(134:389,134:389)=0;
imshow(image_1)
imwrite(image_1,'cropping.png')