<?php

namespace Tests\ApiBundle\Controller;

use ApiBundle\Entity\User;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Functional test for the controllers defined inside BlogController.
 *
 * Execute the application tests using this command (requires PHPUnit to be installed):
 *
 *     $ cd /var/www/html/authOauth/
 *     $ phpunit -c app
 */
class UserControllerTest extends WebTestCase
{
    public function testRegularUsersCannotAccessToTheBackend()
    {
        $client = static::createClient([], [
            'PHP_AUTH_USER' => 'aUser',
            'PHP_AUTH_PW' => 'test1test1',
        ]);

        $url = $client->getContainer()->get('router')->generate('admin_user_index');
        $client->request('GET', $url);
        // echo $client->getResponse()->getContent();die;

        $this->assertEquals(Response::HTTP_FORBIDDEN, $client->getResponse()->getStatusCode());
    }

    public function testAdministratorUsersCanAccessToTheBackend()
    {
        $client = static::createClient([], [
            'PHP_AUTH_USER' => 'admin',
            'PHP_AUTH_PW' => 'admin',
        ]);

        $url = $client->getContainer()->get('router')->generate('admin_user_index');
        $client->request('GET', $url);

        $this->assertEquals(Response::HTTP_OK, $client->getResponse()->getStatusCode());
    }

    public function testNormalUsersCannotAccessAdminLink()
    {
        $client = static::createClient([], [
            'PHP_AUTH_USER' => 'aUser',
            'PHP_AUTH_PW' => 'test1test1',
        ]);

        $url = $client->getContainer()->get('router')->generate('user_index');
        $crawler = $client->request('GET', $url);

        $this->assertCount(
            0,
            $crawler->filterXPath("//a[contains(.,'Admin')]"),
            'The Backend->Admin does not exist for normal user.'
        );
    }

    public function testAdminUsersCanAccessAdminLink()
    {
        $client = static::createClient([], [
            'PHP_AUTH_USER' => 'admin',
            'PHP_AUTH_PW' => 'admin',
        ]);

        $url = $client->getContainer()->get('router')->generate('admin_user_index');
        $crawler = $client->request('GET', $url);

        $this->assertCount(
            1,
            $crawler->filterXPath("//a[contains(.,'Admin')]"),
            'The Backend->Admin does exist for admin user.'
        );
    }

    public function testUserManagementList()
    {
        $client = static::createClient([], [
            'PHP_AUTH_USER' => 'admin',
            'PHP_AUTH_PW' => 'admin',
        ]);

        $url = $client->getContainer()->get('router')->generate('admin_user_index');
        $crawler = $client->request('GET', $url);

        $link = $crawler->selectLink('Admin')->link();
        $client->click($link);

        $link = $crawler->selectLink('User Management')->link();
        $client->click($link);

        $this->assertCount(
            2,
            $crawler->filter('div#main table tbody tr'),
            'The Backend->Admin->User Management page displays all the available users.'
        );
    }
}
