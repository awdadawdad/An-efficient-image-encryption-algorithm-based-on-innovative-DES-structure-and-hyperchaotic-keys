function imgOut = add_noise(imgIn,type,x,y)
% 函数功能：为图像添加噪声
% 关注微信公众号【二进制人工智能】，回复【noise】获取所有代码
% 输入：
%    imgIn：输入图形矩阵，为灰度图像
%    type:字符串，取值随噪声种类而定
%        高斯噪声：gaussian,参数为(x,y)，默认值为(0,10)
%        瑞利噪声： rayleigh,参数为x，默认值为30
%        伽马噪声： gamma,参数为(x,y),默认值为(2,10)
%        指数噪声： exp，参数为x,默认值为15
%        均匀分布： uniform，参数为(x.y)，默认值为(-20,20)
%        椒盐噪声： salt & pepper：强度为x，默认值为0.02
% 输出：
%    imgOut：添加噪声后的图像


% reference from https://blog.csdn.net/weixin_44378835/article/details/109159684

% 预处理
if ndims(imgIn)>=3
    imgIn=rgb2gray(imgIn);
end
[M,N]=size(imgIn);  % 输入图像的大小
% 设置默认噪声类型
if nargin==1
    type='gaussian';
end
% 开始处理
switch lower(type)
    case 'gaussian'  % 高斯噪声
        if nargin<4
            y=10;
        end
        if nargin<3
            x=0;
        end
        % 产生高斯分布随机数
        R=normrnd(x,y,M,N);
        imgOut=double(imgIn)+R;
        imgOut=uint8(round(imgOut));
    case 'uniform' % 均匀分布
        if nargin<4
            y=20;
        end
        if nargin<3
            x=-20;
        end
        % 产生均匀分布随机数
        R=unifrnd(x,y,M,N);
        imgOut=double(imgIn)+R;
        imgOut=uint8(round(imgOut));
    case 'salt & pepper'  % 椒盐噪声
        imgOut=imnoise(imgIn,'salt & pepper',x);
        if nargin<3
            x=0.02;
        end
        a1=rand(M,N)<x;  
        a2=rand(M,N)<x;
        imgOut=imgIn;
        imgOut(a1)=0; 
        imgOut(a2)=255;
    case 'rayleigh'        % 瑞利噪声
        if nargin<3
            x=30;
        end
        R=raylrnd(x,M,N);
        imgOut=double(imgIn)+R;
        imgOut=uint8(round(imgOut));
    case 'exp'             % 指数噪声
        if nargin<3
            x=15;
        end
        R=exprnd(x,M,N);
        imgOut=double(imgIn)+R;
        imgOut=uint8(round(imgOut));
    case 'gamma'   % 伽马噪声
        if nargin<4
            y=10;
        end
        if nargin<3
           x=2;
        end
        R=gamrnd(x,y,M,N);
        imgOut=double(imgIn)+R;
        imgOut=uint8(round(imgOut));
    otherwise
        error('Unkown distribution type')    
end
end