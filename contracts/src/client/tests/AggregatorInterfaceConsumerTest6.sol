// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "../AggregatorV2V3Interface.sol";

/**
 * @dev Test consuming AggregatorV2V3Interface using Solidity version 0.6.x
 */
contract AggregatorInterfaceConsumerTest6 {

  AggregatorV2V3Interface public priceFeed;

  /**
   * @param feed AggregatorV2V3Interface
   */
  constructor(
    AggregatorV2V3Interface feed
  )
    public
  {
    priceFeed = feed;
  }

  /**
   * @notice Get the latest price from the price feed
   * @return price int256
   */
  function getLatestPrice()
    public
    view
    returns(
      int256
    )
  {
    return priceFeed.latestAnswer();
  }
}