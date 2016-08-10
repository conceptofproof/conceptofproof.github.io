---
layout: post
published: true
title: ' Resize and store all your image uploads in the cloud (Laravel 5.2 / S3)'
---
Using the [Laravel](https://laravel.com/) PHP framework with [Amazon S3](https://aws.amazon.com/s3/) we're going to upload files to highly scalable and secure cloud storage using expressive code. The premise is similiar across frameworks, cloud storage providers and hosting environments.

This tutorial assumes you have a very basic understanding of Laravel and have setup your environment i.e followed the [quickstart](https://laravel.com/docs/5.2/quickstart). 

To begin you will need to add the following HTML form into one of your view files. It uploads files via the POST method.

~~~
<form method="POST" action="/upload" enctype="multipart/form-data">

        <input type="hidden" name="_token" value="{{ csrf_token() }}">

        <input name="image" type="file"/>

        <button type="submit">Upload</button>
        
</form>
~~~

You will then need to setup a route and controller if you haven't done so already.

~~~
Route::post('/uploads', 'UploadController@store');
~~~

And the controller named '_UploadController_' for this form to submit to:

~~~
$ php artisan make:controller UploadController
~~~

We can then access the file upload in the _store_ function of the UploadController by accessing the **$request** dependency which can be injected into the method and automatically resolved by Laravel.

To perform the resize and saving to disk we need the [Image intervention](http://image.intervention.io/) PHP package which can be installed via _Composer_ by adding the following into your Composer.json:

~~~
"require": {
	"php": ">=5.5.9",
	"laravel/framework": "5.2.*",
	"intervention/image": "2.3.7",
	"ext-gd": "*",
	"league/flysystem-aws-s3-v3": "~1.0"
}
~~~

Note you may need to specify an exact version of intervention/image to prevent version lookup, this is because Laravel can run artisan before resolving all the composer packages and the config file of Laravel will contain an error if package classes don't yet exist.

Now we can make the store function to upload the image in the _UploadController_.

~~~

public function store(Request $request) {

	$image = $request->file('image');

	$filename = time() . '.' . $image->getClientOriginalExtension();

	$path = public_path('images/' . $filename);

	$imageFile = Image::make($image->getRealPath())->resize(300, 300)->save($path);

	return back();

}  
~~~  

<br/>

## Storing uploaded images to Amazons Cloud Storage

In the next section of the tutorial we'll look at how to configure _Amazon S3_ to work seamlessly with Laravel.

To begin head over to AWS and create a new S3 bucket. I've created mine in IRELAND (eu-west-1), and named it 'mybucket'.

Then add the following AWS bucket policy allowing anyone to make get requests to your files.

~~~
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
~~~

Next you can generate a key and secret key for the root user but for security reasons it's advised to [create new IAM users](https://console.aws.amazon.com/iam/home#users).

Then we need to generate an Access Key for that user (you will only have one opportunity to download or save the secret key before the modal closes)

The next step is to add the keys to your .env file like so:

~~~
S3_KEY=ABCDINSV53CDOO5XO52A
S3_SECRET=1234gSdnVKGYnQGLkSI7yWhV9E7R08OlX+fo7qmS
S3_BUCKET=mybucket
S3_REGION=eu-west-1
~~~

To configure Laravel to use S3 as a disk driver we need to enable S3 driver in the file config/filesystems.php:

~~~
's3' => [
            'driver' => 's3',
            'key'    => env('S3_KEY',''),
            'secret' => env('S3_SECRET',''),
            'region' => env('S3_REGION',''),
            'bucket' => env('S3_BUCKET',''),
        ]
~~~


Finally use [Laravels Storage Facade](https://laravel.com/docs/master/filesystem) to put the files into your bucket on upload:

~~~
	$imageStream = $imageFile->stream();

	Storage::disk('s3')->put($filename, $imageStream->__toString());
~~~

Finally we can fetch the generated S3 URL using the result from the url() function. For example we can save this into a database.

~~~
Storage::disk('s3')->url($s3Path);
~~~

It may not be required to use the _GD php_ extension or you may prefer to use Imagick, you can do this using the following and by editing config/image.php.

~~~
$ php artisan vendor:publish --provider="Intervention\Image\ImageServiceProviderLaravel5"
~~~
