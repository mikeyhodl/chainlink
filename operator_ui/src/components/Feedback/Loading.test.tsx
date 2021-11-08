import React from 'react'
import { render, screen } from 'support/test-utils'
import { Loading } from './Loading'

const { queryByRole } = screen

it('shows a loading spinner', () => {
  render(<Loading />)

  expect(queryByRole('progressbar')).toBeInTheDocument()
})
