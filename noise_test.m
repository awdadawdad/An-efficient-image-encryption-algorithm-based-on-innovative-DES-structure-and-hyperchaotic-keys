clc;clear
image=imread('C:\Users\gaiya\Desktop\論文matlab\Cipheredimage.png');
a = add_noise(image,'salt & pepper',0.05);
imshow(a);
imwrite(a,'noise_Cipheredimage.png')