---
layout: post
published: true
title: Untitled
---
## A New Post

Enter text in [Markdown](http://daringfireball.net/projects/markdown/). Use the toolbar above, or click the **?** button for formatting help.

laravel intervention image amazon web 3

http://image.intervention.io/



"require": {
        "php": ">=5.5.9",
        "laravel/framework": "5.2.*",
        "intervention/image": "2.3.7",
        "ext-gd": "*",
        "league/flysystem-aws-s3-v3": "~1.0"
    },


$image = $request->file('image');
        $filename = time() . '.' . $image->getClientOriginalExtension();

        $path = public_path('images/' . $filename);

$imageFile = Image::make($image->getRealPath())->resize(300, 300)->save($path);


1. Create bucket IRELAND (eu-west-1) 'mybucket'

Then add an AWS bucket policy allowing anyone to make get requests to your files.

{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "PublicReadGetObject",
			"Effect": "Allow",
			"Principal": "*",
			"Action": "s3:GetObject",
			"Resource": "arn:aws:s3:::mybucket/*"
		}
	]
}

2. Create Iam User 
https://console.aws.amazon.com/iam/home#users

and Generate an Access Key for that user (you will only have one oppurtunity to download or save the secret key before the modal closes)

3. Then Add the keys to your .env file:

S3_KEY=ABCDINSV53CDOO5XO52A
S3_SECRET=1234gSdnVKGYnQGLkSI7yWhV9E7R08OlX+fo7qmS
S3_BUCKET=mybucket
S3_REGION=eu-west-1


Enable S3 driver in the file config/filesystems.php:

's3' => [
            'driver' => 's3',
            'key'    => env('S3_KEY',''),
            'secret' => env('S3_SECRET',''),
            'region' => env('S3_REGION',''),
            'bucket' => env('S3_BUCKET',''),
        ],



Finally use Laravels Storage Facade (https://laravel.com/docs/master/filesystem) to put the files into your bucket on upload:

        $imageStream = $imageFile->stream();

        Storage::disk('s3')->put($filename, $imageStream->__toString());

        It may nto be required to use the GD php extension or you may prefer to use Imagick, you can do this using the following:

        $ php artisan vendor:publish --provider="Intervention\Image\ImageServiceProviderLaravel5"

        and then by editing config/image.php
