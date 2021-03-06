<?php

namespace App\Events\Customer;

use App\Customer;
use Illuminate\Broadcasting\Channel;
use Illuminate\Queue\SerializesModels;
use Illuminate\Foundation\Events\Dispatchable;

class CustomerProfileUpdated
{
    use Dispatchable, SerializesModels;

    public $customer;

    /**
     * Create a new job instance.
     *
     * @param  Customer  $customer
     * @return void
     */
    public function __construct(Customer $customer)
    {
        $this->customer = $customer;
    }
}
